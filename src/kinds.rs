//! Function name → semantic kind. Drives which arguments the BPF programs
//! may read. Anything unrecognized is OTHER (no argument capture), and an
//! aliased slot whose names disagree degrades to OTHER: reading the wrong
//! argument shape could touch a PIN pointer, so ambiguity never guesses.

use p11scope_ebpf_common::{
    MAX_DESCRIPTORS, SlotSemantics, direct, lifecycle, operation, semantic_flags, transition,
};
use std::sync::LazyLock;

pub fn function_id(name: &str) -> Option<u32> {
    pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
        .position(|field| field.name == name)
        .map(|index| index as u32)
}

/// Fixed capture-independent descriptors. Index zero is count-only; each
/// canonical published function follows at `function_id(name) + 1`.
pub static DESCRIPTORS: LazyLock<[SlotSemantics; MAX_DESCRIPTORS as usize]> = LazyLock::new(|| {
    let mut descriptors = [SlotSemantics::COUNT_ONLY; MAX_DESCRIPTORS as usize];
    for (index, field) in pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
        .enumerate()
    {
        descriptors[index + 1] = descriptor(field.name)
            .unwrap_or_else(|| panic!("{} lacks a capture descriptor", field.name));
    }
    descriptors
});

/// Select one fixed descriptor for one static target. Unknown names and
/// conflicting aliases must remain count-only; agreeing aliases choose the
/// lowest canonical function id, independent of discovery ordering.
pub fn descriptor_index(names: &[String]) -> (u32, bool) {
    if names.is_empty() {
        return (0, false);
    }

    let mut index: Option<u32> = None;
    let mut selected = SlotSemantics::COUNT_ONLY;
    for name in names {
        let Some(function_id) = function_id(name) else {
            return (0, true);
        };
        let candidate = DESCRIPTORS[(function_id + 1) as usize];
        if let Some(previous) = index {
            if candidate != selected {
                return (0, true);
            }
            index = Some(previous.min(function_id + 1));
        } else {
            selected = candidate;
            index = Some(function_id + 1);
        }
    }
    (index.unwrap_or(0), false)
}

pub fn descriptor_slot(names: &[String]) -> (SlotSemantics, bool) {
    let (index, ambiguous) = descriptor_index(names);
    (DESCRIPTORS[index as usize], ambiguous)
}

fn session(operations: u16, transition: u8) -> SlotSemantics {
    SlotSemantics {
        operations,
        transition,
        session_arg: 0,
        ..SlotSemantics::COUNT_ONLY
    }
}

fn init(operation: u16, null_cancel: bool) -> SlotSemantics {
    SlotSemantics {
        operations: operation,
        transition: transition::INITIALIZE,
        semantic_flags: if null_cancel {
            semantic_flags::NULL_MECHANISM_CANCEL
        } else {
            0
        },
        session_arg: 0,
        mechanism_arg: 1,
        ..SlotSemantics::COUNT_ONLY
    }
}

fn lifecycle_only(action: u8) -> SlotSemantics {
    SlotSemantics {
        lifecycle: action,
        ..SlotSemantics::COUNT_ONLY
    }
}

fn direct_operation(kind: u8) -> SlotSemantics {
    SlotSemantics {
        direct: kind,
        session_arg: 0,
        mechanism_arg: 1,
        ..SlotSemantics::COUNT_ONLY
    }
}

fn with_template(mut value: SlotSemantics, template: u8, count: u8) -> SlotSemantics {
    value.template0_arg = template;
    value.template_count0_arg = count;
    value
}

fn with_output(mut value: SlotSemantics, output: u8) -> SlotSemantics {
    value.output_arg = output;
    value
}

/// Exact standard function name to capture/state descriptor. `None` is
/// reserved for names outside the shared published 104-slot inventory.
pub fn descriptor(name: &str) -> Option<SlotSemantics> {
    let value = match name {
        "C_Initialize" | "C_GetInfo" | "C_GetFunctionList" | "C_GetSlotList"
        | "C_GetInterfaceList" | "C_GetInterface" => SlotSemantics::COUNT_ONLY,

        "C_Finalize" => lifecycle_only(lifecycle::FINALIZE),
        "C_GetSlotInfo" | "C_GetTokenInfo" | "C_GetMechanismList" | "C_GetMechanismInfo"
        | "C_InitToken" => SlotSemantics {
            slot_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_InitPIN"
        | "C_SetPIN"
        | "C_GetSessionInfo"
        | "C_GetOperationState"
        | "C_DestroyObject"
        | "C_GetObjectSize"
        | "C_SeedRandom"
        | "C_GenerateRandom"
        | "C_GetFunctionStatus"
        | "C_CancelFunction"
        | "C_GetSessionValidationFlags" => session(0, transition::NONE),

        "C_OpenSession" => SlotSemantics {
            lifecycle: lifecycle::OPEN_SESSION,
            slot_arg: 0,
            flags_arg: 1,
            output_arg: 4,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_CloseSession" => SlotSemantics {
            lifecycle: lifecycle::CLOSE_SESSION,
            session_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_CloseAllSessions" => SlotSemantics {
            lifecycle: lifecycle::CLOSE_ALL_SESSIONS,
            slot_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_SetOperationState" => SlotSemantics {
            lifecycle: lifecycle::SET_OPERATION_STATE,
            session_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_Login" | "C_LoginUser" => SlotSemantics {
            lifecycle: lifecycle::LOGIN,
            session_arg: 0,
            user_type_arg: 1,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_Logout" => SlotSemantics {
            lifecycle: lifecycle::LOGOUT,
            session_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },

        "C_CreateObject" | "C_FindObjectsInit" => {
            let lifecycle = if name == "C_FindObjectsInit" {
                lifecycle::FIND_INIT
            } else {
                0
            };
            let mut value = with_template(session(0, transition::NONE), 1, 2);
            value.lifecycle = lifecycle;
            value
        }
        "C_CopyObject" | "C_SetAttributeValue" => with_template(session(0, transition::NONE), 2, 3),
        "C_GetAttributeValue" => {
            let mut value = with_template(session(0, transition::NONE), 2, 3);
            value.semantic_flags |= semantic_flags::TEMPLATE0_TYPES_ONLY;
            value
        }
        "C_FindObjectsFinal" => SlotSemantics {
            lifecycle: lifecycle::FIND_FINAL,
            session_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_FindObjects" => SlotSemantics {
            lifecycle: lifecycle::FIND_OPERATION,
            session_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },

        "C_EncryptInit" => init(operation::ENCRYPT, true),
        "C_DecryptInit" => init(operation::DECRYPT, true),
        "C_DigestInit" => init(operation::DIGEST, true),
        "C_SignInit" => init(operation::SIGN, true),
        "C_SignRecoverInit" => init(operation::SIGN_RECOVER, true),
        "C_VerifyInit" => init(operation::VERIFY, true),
        "C_VerifyRecoverInit" => init(operation::VERIFY_RECOVER, true),

        "C_Encrypt" => with_output(
            session(operation::ENCRYPT, transition::FINISH_WITH_OUTPUT),
            3,
        ),
        "C_Decrypt" => with_output(
            session(operation::DECRYPT, transition::FINISH_WITH_OUTPUT),
            3,
        ),
        "C_Digest" => with_output(
            session(operation::DIGEST, transition::FINISH_WITH_OUTPUT),
            3,
        ),
        "C_Sign" => with_output(session(operation::SIGN, transition::FINISH_WITH_OUTPUT), 3),
        "C_SignRecover" => with_output(
            session(operation::SIGN_RECOVER, transition::FINISH_WITH_OUTPUT),
            3,
        ),
        "C_VerifyRecover" => with_output(
            session(operation::VERIFY_RECOVER, transition::FINISH_WITH_OUTPUT),
            3,
        ),
        "C_EncryptFinal" => with_output(
            session(operation::ENCRYPT, transition::FINISH_WITH_OUTPUT),
            1,
        ),
        "C_DecryptFinal" => with_output(
            session(operation::DECRYPT, transition::FINISH_WITH_OUTPUT),
            1,
        ),
        "C_DigestFinal" => with_output(
            session(operation::DIGEST, transition::FINISH_WITH_OUTPUT),
            1,
        ),
        "C_SignFinal" => with_output(session(operation::SIGN, transition::FINISH_WITH_OUTPUT), 1),
        "C_Verify" | "C_VerifyFinal" => session(operation::VERIFY, transition::FINISH_ALWAYS),

        "C_EncryptUpdate" => with_output(
            session(operation::ENCRYPT, transition::UPDATE_WITH_OUTPUT),
            3,
        ),
        "C_DecryptUpdate" => with_output(
            session(operation::DECRYPT, transition::UPDATE_WITH_OUTPUT),
            3,
        ),
        "C_DigestUpdate" => session(operation::DIGEST, transition::CONTINUE),
        "C_SignUpdate" => session(operation::SIGN, transition::CONTINUE),
        "C_VerifyUpdate" => session(operation::VERIFY, transition::CONTINUE),
        "C_DigestKey" => session(operation::DIGEST, transition::RETAIN_ALWAYS),
        "C_DigestEncryptUpdate" => with_output(
            session(
                operation::DIGEST | operation::ENCRYPT,
                transition::RETAIN_ALWAYS,
            ),
            3,
        ),
        "C_DecryptDigestUpdate" => with_output(
            session(
                operation::DECRYPT | operation::DIGEST,
                transition::RETAIN_ALWAYS,
            ),
            3,
        ),
        "C_SignEncryptUpdate" => with_output(
            session(
                operation::SIGN | operation::ENCRYPT,
                transition::RETAIN_ALWAYS,
            ),
            3,
        ),
        "C_DecryptVerifyUpdate" => with_output(
            session(
                operation::DECRYPT | operation::VERIFY,
                transition::RETAIN_ALWAYS,
            ),
            3,
        ),

        "C_GenerateKey" => with_template(direct_operation(direct::GENERATE_KEY), 2, 3),
        "C_GenerateKeyPair" => {
            let mut value = with_template(direct_operation(direct::GENERATE_KEY_PAIR), 2, 3);
            value.template1_arg = 4;
            value.template_count1_arg = 5;
            value
        }
        "C_WrapKey" => with_output(direct_operation(direct::WRAP), 4),
        "C_UnwrapKey" => with_template(direct_operation(direct::UNWRAP), 5, 6),
        "C_DeriveKey" => with_template(direct_operation(direct::DERIVE), 3, 4),
        "C_WaitForSlotEvent" => SlotSemantics {
            flags_arg: 0,
            ..SlotSemantics::COUNT_ONLY
        },

        "C_SessionCancel" => SlotSemantics {
            lifecycle: lifecycle::SESSION_CANCEL,
            session_arg: 0,
            flags_arg: 1,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_MessageEncryptInit" => init(operation::MESSAGE_ENCRYPT, true),
        "C_MessageDecryptInit" => init(operation::MESSAGE_DECRYPT, false),
        "C_MessageSignInit" => init(operation::MESSAGE_SIGN, false),
        "C_MessageVerifyInit" => init(operation::MESSAGE_VERIFY, false),
        "C_EncryptMessage" | "C_EncryptMessageBegin" | "C_EncryptMessageNext" => {
            session(operation::MESSAGE_ENCRYPT, transition::RETAIN_ALWAYS)
        }
        "C_DecryptMessage" | "C_DecryptMessageBegin" | "C_DecryptMessageNext" => {
            session(operation::MESSAGE_DECRYPT, transition::RETAIN_ALWAYS)
        }
        "C_SignMessage" | "C_SignMessageBegin" | "C_SignMessageNext" => {
            session(operation::MESSAGE_SIGN, transition::RETAIN_ALWAYS)
        }
        "C_VerifyMessage" | "C_VerifyMessageBegin" | "C_VerifyMessageNext" => {
            session(operation::MESSAGE_VERIFY, transition::RETAIN_ALWAYS)
        }
        "C_MessageEncryptFinal" => {
            session(operation::MESSAGE_ENCRYPT, transition::FINISH_ON_SUCCESS)
        }
        "C_MessageDecryptFinal" => {
            session(operation::MESSAGE_DECRYPT, transition::FINISH_ON_SUCCESS)
        }
        "C_MessageSignFinal" => session(operation::MESSAGE_SIGN, transition::FINISH_ON_SUCCESS),
        "C_MessageVerifyFinal" => session(operation::MESSAGE_VERIFY, transition::FINISH_ON_SUCCESS),

        "C_EncapsulateKey" => {
            let value = with_template(direct_operation(direct::ENCAPSULATE), 3, 4);
            with_output(value, 5)
        }
        "C_DecapsulateKey" => with_template(direct_operation(direct::DECAPSULATE), 3, 4),
        "C_VerifySignatureInit" => init(operation::VERIFY, true),
        "C_VerifySignature" | "C_VerifySignatureFinal" => {
            session(operation::VERIFY, transition::FINISH_ALWAYS)
        }
        "C_VerifySignatureUpdate" => session(operation::VERIFY, transition::CONTINUE),
        "C_AsyncComplete" => SlotSemantics {
            lifecycle: lifecycle::ASYNC_COMPLETE,
            session_arg: 0,
            async_name_arg: 1,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_AsyncGetID" => SlotSemantics {
            lifecycle: lifecycle::ASYNC_GET_ID,
            session_arg: 0,
            async_name_arg: 1,
            async_value_arg: 2,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_AsyncJoin" => SlotSemantics {
            lifecycle: lifecycle::ASYNC_JOIN,
            session_arg: 0,
            async_name_arg: 1,
            async_value_arg: 2,
            ..SlotSemantics::COUNT_ONLY
        },
        "C_WrapKeyAuthenticated" => with_output(direct_operation(direct::WRAP_AUTHENTICATED), 6),
        "C_UnwrapKeyAuthenticated" => {
            with_template(direct_operation(direct::UNWRAP_AUTHENTICATED), 5, 6)
        }
        _ => return None,
    };
    debug_assert!(value.argument_indices().all(|index| index <= 6));
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_published_32_slot_has_an_explicit_safe_descriptor() {
        let fields = pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS);
        let mut count = 0;
        for field in fields {
            let descriptor = descriptor(field.name)
                .unwrap_or_else(|| panic!("{} fell through as unknown", field.name));
            for index in descriptor.argument_indices() {
                assert!(
                    index <= 6,
                    "{} reads forbidden argument {index}",
                    field.name
                );
            }
            let has_template = descriptor.template0_arg != p11scope_ebpf_common::ARG_NONE
                || descriptor.template1_arg != p11scope_ebpf_common::ARG_NONE;
            assert!(
                !has_template || descriptor.async_name_arg == p11scope_ebpf_common::ARG_NONE,
                "{} combines template and async capture",
                field.name
            );
            count += 1;
        }
        assert_eq!(count, 104);
        assert!(descriptor("C_NotAStandardFunction").is_none());
    }

    #[test]
    fn termination_and_high_argument_boundaries_are_exact() {
        assert_eq!(
            descriptor("C_Verify").unwrap().transition,
            transition::FINISH_ALWAYS
        );
        assert_eq!(
            descriptor("C_VerifyRecover").unwrap().transition,
            transition::FINISH_WITH_OUTPUT
        );
        assert_eq!(descriptor("C_VerifyRecover").unwrap().output_arg, 3);
        assert_eq!(descriptor("C_SignRecover").unwrap().output_arg, 3);
        assert_eq!(
            descriptor("C_UnwrapKeyAuthenticated")
                .unwrap()
                .template_count0_arg,
            6
        );
        assert_eq!(
            descriptor("C_UnwrapKeyAuthenticated")
                .unwrap()
                .mechanism_arg,
            1
        );
    }

    #[test]
    fn descriptor_aliases_must_agree_exactly() {
        let agreeing = vec!["C_InitPIN".to_string(), "C_SetPIN".to_string()];
        assert!(!descriptor_slot(&agreeing).1);

        let disagreeing = vec!["C_SignInit".to_string(), "C_VerifyInit".to_string()];
        let (descriptor, ambiguous) = descriptor_slot(&disagreeing);
        assert!(ambiguous);
        assert_eq!(descriptor, SlotSemantics::COUNT_ONLY);
    }

    /// Mutation caught: a reordered, incomplete, or permissive descriptor
    /// inventory could grant capture semantics to an unknown or conflicting target.
    #[test]
    fn descriptor_indices_are_canonical_and_fail_closed() {
        assert_eq!(DESCRIPTORS[0], SlotSemantics::COUNT_ONLY);
        assert_eq!(DESCRIPTORS.len(), 105);
        for field in pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
        {
            let index = function_id(field.name).unwrap() + 1;
            assert_eq!(DESCRIPTORS[index as usize], descriptor(field.name).unwrap());
        }

        let sign = vec!["C_SignInit".to_string()];
        assert_eq!(
            descriptor_index(&sign),
            (function_id("C_SignInit").unwrap() + 1, false)
        );
        let aliases = vec!["C_InitPIN".to_string(), "C_SetPIN".to_string()];
        assert_eq!(
            descriptor_index(&aliases),
            (function_id("C_InitPIN").unwrap() + 1, false)
        );
        let unknown = vec!["C_NotAStandardFunction".to_string()];
        assert_eq!(descriptor_index(&unknown), (0, true));
        let conflicting = vec!["C_SignInit".to_string(), "C_VerifyInit".to_string()];
        assert_eq!(descriptor_index(&conflicting), (0, true));
    }
}
