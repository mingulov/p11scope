//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private authority carried from retained Inventory inputs to a Detailed lane.

/// Finite refusal; no private manifest or native record is rendered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticRefusal {
    ManifestInput,
    Unattested,
    IncompleteProvider,
    Attachment,
    Descriptor,
    ProviderInstanceUnproven,
}

impl std::fmt::Display for SemanticRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ManifestInput => "manifest_input_refused",
            Self::Unattested => "unattested",
            Self::IncompleteProvider => "incomplete_provider",
            Self::Attachment => "semantic_attachment_refused",
            Self::Descriptor => "semantic_descriptor_refused",
            Self::ProviderInstanceUnproven => "provider_instance_unproven",
        })
    }
}

pub(crate) use crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset;
