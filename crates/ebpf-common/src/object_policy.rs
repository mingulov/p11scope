//! SPDX-License-Identifier: GPL-2.0-or-later
//! Finite object policy from the reviewed proposed privacy allowlist v3.
//!
//! These pure definitions perform no reads and activate no capture. A caller
//! must still establish descriptor, provider, image, ABI and call ownership,
//! then apply the action's entry/return protocol before using an argument.
//! None of these types is a wire layout or a raw pointer/handle container.

use crate::{LinuxLayout, ARG_NONE};

/// The entire allowed attribute-selector vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeAttributeKind {
    Class,
    KeyType,
    Token,
    ValueLen,
    ModulusBits,
    EcParams,
}

/// Only complete, exact encodings of these curves may be classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeCurve {
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

/// Compare the entire target word; excluded/unknown selectors gain no reads.
pub const fn safe_attribute_kind(raw: u64) -> Option<SafeAttributeKind> {
    match raw {
        0x0000 => Some(SafeAttributeKind::Class),
        0x0001 => Some(SafeAttributeKind::Token),
        0x0100 => Some(SafeAttributeKind::KeyType),
        0x0121 => Some(SafeAttributeKind::ModulusBits),
        0x0161 => Some(SafeAttributeKind::ValueLen),
        0x0180 => Some(SafeAttributeKind::EcParams),
        _ => None,
    }
}

/// Validate an exact value length against the target ABI, never host width.
/// This does not establish readable spans, capacity or unchanged headers.
pub const fn valid_safe_attribute_length(
    kind: SafeAttributeKind,
    len: u64,
    layout: LinuxLayout,
) -> bool {
    match kind {
        SafeAttributeKind::Token => len == 1,
        SafeAttributeKind::EcParams => len == 7 || len == 10,
        _ => len == layout.word_bytes() as u64,
    }
}

/// Return the exact approved scalar only after full-width membership checks.
/// A size fact alone establishes no key type, and requested facts establish no
/// result properties. `EcParams` requires complete bytes instead of a scalar.
pub const fn classify_attribute_scalar(kind: SafeAttributeKind, value: u64) -> Option<u16> {
    match (kind, value) {
        (SafeAttributeKind::Class, 0..=4)
        | (SafeAttributeKind::KeyType, 0x00..=0x04 | 0x10 | 0x1f | 0x3a | 0x3b)
        | (SafeAttributeKind::Token, 0 | 1)
        | (SafeAttributeKind::ValueLen, 16 | 24 | 32)
        | (SafeAttributeKind::ModulusBits, 1024 | 2048 | 3072 | 4096 | 8192) => Some(value as u16),
        _ => None,
    }
}

/// Exact complete-byte equality only; no DER parser or prefix fallback.
pub fn classify_ec_params(bytes: &[u8]) -> Option<SafeCurve> {
    match bytes {
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some(SafeCurve::Secp256r1),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => Some(SafeCurve::Secp384r1),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] => Some(SafeCurve::Secp521r1),
        _ => None,
    }
}

/// Operation roles determine the distinct result and template protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectAction {
    Create,
    Copy,
    Generate,
    GeneratePair,
    Derive,
    Unwrap,
    Destroy,
    Access,
    OperationImport,
    Find,
    GetAttributes,
    SetAttributes,
}

/// Additional entry evidence needed before result-pointer/template access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultProtocolGuard {
    NamedFunction,
    ScalarDeriveMechanism,
}

/// Argument indices are policy, not read authority by themselves.
///
/// Creation templates describe requests. `GetAttributes` uses template pair
/// zero only for its separate capacity/header/partial-return protocol; it does
/// not authorize reading request values. `Find` uses result position zero for
/// the bounded array, guarded by its capacity/count protocol, not one handle.
/// `SetAttributes` authorizes no template read. For `Derive`, the same finite
/// mechanism guard precedes both result-pointer retention and template reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectCaptureDescriptor {
    /// Scalar handles only. Operation-import zero values mean absent keys.
    /// An Init's existing successful null-mechanism cancellation transition
    /// must precede object processing and produces no key access observation.
    pub input_args: [u8; 2],
    pub result_pointer_args: [u8; 2],
    pub template_args: [(u8, u8); 2],
    pub find_capacity_arg: u8,
    pub find_count_ptr_arg: u8,
    pub action: ObjectAction,
    pub result_protocol_guard: ResultProtocolGuard,
}

impl ObjectCaptureDescriptor {
    const fn new(action: ObjectAction) -> Self {
        Self {
            input_args: [ARG_NONE; 2],
            result_pointer_args: [ARG_NONE; 2],
            template_args: [(ARG_NONE, ARG_NONE); 2],
            find_capacity_arg: ARG_NONE,
            find_count_ptr_arg: ARG_NONE,
            action,
            result_protocol_guard: ResultProtocolGuard::NamedFunction,
        }
    }
}

/// Look up only the named combinations in the frozen standard catalog.
/// Unknown ordinals and unlisted standard/vendor functions fail closed.
pub fn object_descriptor(function: u32) -> Option<ObjectCaptureDescriptor> {
    let name = pkcs11_module::function_name(function as usize)?;
    let descriptor = match name {
        "C_CreateObject" => ObjectCaptureDescriptor {
            result_pointer_args: [3, ARG_NONE],
            template_args: [(1, 2), (ARG_NONE, ARG_NONE)],
            ..ObjectCaptureDescriptor::new(ObjectAction::Create)
        },
        "C_CopyObject" => ObjectCaptureDescriptor {
            input_args: [1, ARG_NONE],
            result_pointer_args: [4, ARG_NONE],
            template_args: [(2, 3), (ARG_NONE, ARG_NONE)],
            ..ObjectCaptureDescriptor::new(ObjectAction::Copy)
        },
        "C_GenerateKey" => ObjectCaptureDescriptor {
            result_pointer_args: [4, ARG_NONE],
            template_args: [(2, 3), (ARG_NONE, ARG_NONE)],
            ..ObjectCaptureDescriptor::new(ObjectAction::Generate)
        },
        "C_GenerateKeyPair" => ObjectCaptureDescriptor {
            result_pointer_args: [6, 7],
            template_args: [(2, 3), (4, 5)],
            ..ObjectCaptureDescriptor::new(ObjectAction::GeneratePair)
        },
        "C_DeriveKey" => ObjectCaptureDescriptor {
            input_args: [2, ARG_NONE],
            result_pointer_args: [5, ARG_NONE],
            template_args: [(3, 4), (ARG_NONE, ARG_NONE)],
            result_protocol_guard: ResultProtocolGuard::ScalarDeriveMechanism,
            ..ObjectCaptureDescriptor::new(ObjectAction::Derive)
        },
        "C_UnwrapKey" => ObjectCaptureDescriptor {
            input_args: [2, ARG_NONE],
            result_pointer_args: [7, ARG_NONE],
            template_args: [(5, 6), (ARG_NONE, ARG_NONE)],
            ..ObjectCaptureDescriptor::new(ObjectAction::Unwrap)
        },
        "C_DestroyObject" => ObjectCaptureDescriptor {
            input_args: [1, ARG_NONE],
            ..ObjectCaptureDescriptor::new(ObjectAction::Destroy)
        },
        "C_GetObjectSize" | "C_DigestKey" => ObjectCaptureDescriptor {
            input_args: [1, ARG_NONE],
            ..ObjectCaptureDescriptor::new(ObjectAction::Access)
        },
        "C_GetAttributeValue" => ObjectCaptureDescriptor {
            input_args: [1, ARG_NONE],
            template_args: [(2, 3), (ARG_NONE, ARG_NONE)],
            ..ObjectCaptureDescriptor::new(ObjectAction::GetAttributes)
        },
        "C_SetAttributeValue" => ObjectCaptureDescriptor {
            input_args: [1, ARG_NONE],
            ..ObjectCaptureDescriptor::new(ObjectAction::SetAttributes)
        },
        "C_EncryptInit"
        | "C_DecryptInit"
        | "C_SignInit"
        | "C_SignRecoverInit"
        | "C_VerifyInit"
        | "C_VerifyRecoverInit"
        | "C_MessageEncryptInit"
        | "C_MessageDecryptInit"
        | "C_MessageSignInit"
        | "C_MessageVerifyInit"
        | "C_VerifySignatureInit" => ObjectCaptureDescriptor {
            input_args: [2, ARG_NONE],
            ..ObjectCaptureDescriptor::new(ObjectAction::Access)
        },
        "C_WrapKey" => ObjectCaptureDescriptor {
            input_args: [2, 3],
            ..ObjectCaptureDescriptor::new(ObjectAction::Access)
        },
        "C_SetOperationState" => ObjectCaptureDescriptor {
            input_args: [3, 4],
            ..ObjectCaptureDescriptor::new(ObjectAction::OperationImport)
        },
        "C_FindObjects" => ObjectCaptureDescriptor {
            result_pointer_args: [1, ARG_NONE],
            find_capacity_arg: 2,
            find_count_ptr_arg: 3,
            ..ObjectCaptureDescriptor::new(ObjectAction::Find)
        },
        _ => return None,
    };
    Some(descriptor)
}

/// Every field, including the protocol guard and unused positions, must match.
pub fn valid_object_descriptor(function: u32, candidate: &ObjectCaptureDescriptor) -> bool {
    object_descriptor(function).as_ref() == Some(candidate)
}

/// Keep which accepted mechanism must match the existing return-time evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarDeriveMechanism {
    DhPkcs,
    Sha256,
    Ecdh1,
    Ecdh1Cofactor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveResultProtocol {
    Unavailable,
    ScalarHandle(ScalarDeriveMechanism),
}

/// Full-width membership only. Successful SSL3/TLS12/WTLS calls may leave
/// `phKey` untouched, so neither success nor a nonzero cell authorizes it.
pub const fn derive_result_protocol(mechanism: u64) -> DeriveResultProtocol {
    match mechanism {
        0x21 => DeriveResultProtocol::ScalarHandle(ScalarDeriveMechanism::DhPkcs),
        0x393 => DeriveResultProtocol::ScalarHandle(ScalarDeriveMechanism::Sha256),
        0x1050 => DeriveResultProtocol::ScalarHandle(ScalarDeriveMechanism::Ecdh1),
        0x1051 => DeriveResultProtocol::ScalarHandle(ScalarDeriveMechanism::Ecdh1Cofactor),
        _ => DeriveResultProtocol::Unavailable,
    }
}

/// Apply the entry protocol guard before retaining any nominal result pointer.
/// `None` covers null, unreadable and unavailable mechanism evidence. This
/// permission still requires all call/ABI guards and the action's return
/// protocol; Derive must match the accepted entry mechanism at CKR_OK return.
pub fn authorized_result_pointer_args(function: u32, mechanism: Option<u64>) -> [u8; 2] {
    let Some(descriptor) = object_descriptor(function) else {
        return [ARG_NONE; 2];
    };
    if descriptor.result_protocol_guard == ResultProtocolGuard::ScalarDeriveMechanism {
        let Some(mechanism) = mechanism else {
            return [ARG_NONE; 2];
        };
        if derive_result_protocol(mechanism) == DeriveResultProtocol::Unavailable {
            return [ARG_NONE; 2];
        }
    }
    descriptor.result_pointer_args
}

#[cfg(test)]
mod tests;
