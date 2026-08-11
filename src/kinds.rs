//! Function name → semantic kind. Drives which arguments the BPF programs
//! may read. Anything unrecognized is OTHER (no argument capture), and an
//! aliased slot whose names disagree degrades to OTHER: reading the wrong
//! argument shape could touch a PIN pointer, so ambiguity never guesses.

use p11scope_ebpf_common::fnkind;

pub fn classify(name: &str) -> u32 {
    match name {
        "C_DigestInit" | "C_SignInit" | "C_VerifyInit" | "C_EncryptInit"
        | "C_DecryptInit" | "C_SignRecoverInit" | "C_VerifyRecoverInit" => fnkind::INIT_WITH_MECH,
        "C_OpenSession" => fnkind::OPEN_SESSION,
        "C_Login" => fnkind::LOGIN,
        // Session is arg0 for the operational entry points we care about.
        "C_CloseSession" | "C_CloseAllSessions" | "C_Logout" | "C_GetSessionInfo"
        | "C_Digest" | "C_DigestUpdate" | "C_DigestFinal"
        | "C_Sign" | "C_SignUpdate" | "C_SignFinal"
        | "C_Verify" | "C_VerifyUpdate" | "C_VerifyFinal"
        | "C_Encrypt" | "C_EncryptUpdate" | "C_EncryptFinal"
        | "C_Decrypt" | "C_DecryptUpdate" | "C_DecryptFinal"
        | "C_GenerateKey" | "C_GenerateKeyPair" | "C_WrapKey" | "C_UnwrapKey"
        | "C_DeriveKey" | "C_GenerateRandom" | "C_SeedRandom"
        | "C_FindObjectsInit" | "C_FindObjects" | "C_FindObjectsFinal"
        | "C_GetAttributeValue" | "C_SetAttributeValue"
        | "C_CreateObject" | "C_CopyObject" | "C_DestroyObject" => fnkind::SESSION_ARG0,
        _ => fnkind::OTHER,
    }
}

/// A slot's kind: the shared kind of all its names, or OTHER when they
/// disagree.
pub fn classify_slot(names: &[String]) -> u32 {
    let mut it = names.iter().map(|n| classify(n));
    match it.next() {
        None => fnkind::OTHER,
        Some(first) => {
            if it.all(|k| k == first) { first } else { fnkind::OTHER }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_shapes_classify() {
        assert_eq!(classify("C_DigestInit"), fnkind::INIT_WITH_MECH);
        assert_eq!(classify("C_SignInit"), fnkind::INIT_WITH_MECH);
        assert_eq!(classify("C_OpenSession"), fnkind::OPEN_SESSION);
        assert_eq!(classify("C_Login"), fnkind::LOGIN);
        assert_eq!(classify("C_Digest"), fnkind::SESSION_ARG0);
        assert_eq!(classify("C_Initialize"), fnkind::OTHER);
        assert_eq!(classify("C_WhoKnows"), fnkind::OTHER);
    }

    #[test]
    fn ambiguous_alias_degrades_to_other() {
        // C_Login takes a PIN pointer where an *Init takes a mechanism.
        // Guessing here would be a privacy incident, so it must not guess.
        let names = vec!["C_Login".to_string(), "C_SignInit".to_string()];
        assert_eq!(classify_slot(&names), fnkind::OTHER);
    }

    #[test]
    fn agreeing_alias_keeps_the_kind() {
        let names = vec!["C_SignInit".to_string(), "C_VerifyInit".to_string()];
        assert_eq!(classify_slot(&names), fnkind::INIT_WITH_MECH);
    }

    #[test]
    fn single_name_slot_uses_its_kind() {
        assert_eq!(classify_slot(&["C_OpenSession".to_string()]), fnkind::OPEN_SESSION);
        assert_eq!(classify_slot(&[]), fnkind::OTHER);
    }
}
