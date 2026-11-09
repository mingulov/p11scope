//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Conservative `CKM_*` name → CycloneDX `algorithmProperties` mapping.
//!
//! Every property here is determined by the mechanism's own registered
//! name (or the input's observed operation categories) alone. S1 output
//! carries no sizes, curves or parameters, so those keys are never
//! filled from a name; unregistered ids and unrecognized spellings read
//! `unknown`.

/// CycloneDX `algorithmProperties` for one mechanism name: primitive,
/// mode, padding (each `None` when the name does not determine it) and
/// the observed operation categories rendered as `cryptoFunctions`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct AlgorithmProperties {
    pub primitive: Option<&'static str>,
    pub mode: Option<&'static str>,
    pub padding: Option<&'static str>,
    pub functions: Vec<&'static str>,
}

/// Classify one registered mechanism name. `operations` are the input's
/// observed operation categories for this id (S1 `operations` or
/// profile `ops`); unknown labels read `unknown` per the schema's
/// additive-evolution rule and are also kept verbatim in properties.
pub(crate) fn classify(name: &str, operations: &[String]) -> AlgorithmProperties {
    let (primitive, mode, padding) = primitive_of(name);
    let mut functions: Vec<&'static str> = operations.iter().map(|op| function_of(op)).collect();
    functions.sort_unstable();
    functions.dedup();
    AlgorithmProperties {
        primitive,
        mode,
        padding,
        functions,
    }
}

fn primitive_of(
    name: &str,
) -> (
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
) {
    // Key agreement and derivation first: their `DERIVE` spellings must
    // not fall through to the generic rules below.
    if name.contains("ML_KEM") {
        if name.contains("HYBRID") {
            return (Some("combiner"), None, None);
        }
        return (Some("kem"), None, None);
    }
    if name.contains("ML_DSA") || name.contains("SLH_DSA") {
        return (Some("signature"), None, None);
    }
    if name.contains("ECDH")
        || name.contains("DH_PKCS")
        || name.contains("X9_42")
        || name.contains("MQV")
    {
        return (Some("key-agree"), None, None);
    }
    if name.contains("HKDF") || name.contains("PBKDF") || name.contains("_PRF") {
        return (Some("kdf"), None, None);
    }
    if name.contains("DERIVE") {
        return (Some("kdf"), None, None);
    }
    if name.contains("RSA") {
        return rsa_of(name);
    }
    if name.contains("DSA") {
        // DSA, ECDSA, EdDSA and their parameter/key-pair generations.
        // ECDH matched above; nothing else named `*DSA*` signs nothing.
        return (Some("signature"), None, None);
    }
    if name.contains("HMAC") || name.contains("_CMAC") || name.contains("GMAC") {
        return (Some("mac"), None, None);
    }
    if name.contains("SHAKE") {
        return (Some("xof"), None, None);
    }
    if name.contains("SHA")
        || name.contains("MD2")
        || name.contains("MD5")
        || name.contains("RIPEMD")
        || name.contains("BLAKE")
        || name.contains("GOSTR3411")
        || name.contains("SKEIN")
    {
        return (Some("hash"), None, None);
    }
    if name.contains("CHACHA") || name.contains("SALSA") || name.contains("RC4") {
        if name.contains("POLY1305") {
            return (Some("ae"), Some("other"), None);
        }
        return (Some("stream-cipher"), None, None);
    }
    if name.contains("AES")
        || name.contains("DES")
        || name.contains("CAST")
        || name.contains("RC2")
        || name.contains("RC5")
        || name.contains("IDEA")
        || name.contains("BLOWFISH")
        || name.contains("TWOFISH")
        || name.contains("SEED")
        || name.contains("CAMELLIA")
        || name.contains("ARIA")
        || name.contains("SM4")
        || name.contains("GOST28147")
        || name.contains("SKIPJACK")
        || name.contains("BATON")
        || name.contains("JUNIPER")
        || name.contains("CDMF")
    {
        return block_cipher_of(name);
    }
    (Some("unknown"), None, None)
}

fn rsa_of(
    name: &str,
) -> (
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
) {
    if name.contains("OAEP") {
        return (Some("pke"), None, Some("oaep"));
    }
    if name.contains("PSS") {
        return (Some("signature"), None, Some("other"));
    }
    if name.contains("X9_31") || name.contains("9796") {
        return (Some("signature"), None, Some("other"));
    }
    if name.contains("X_509") {
        return (Some("pke"), None, Some("raw"));
    }
    // Key generation names the family, not a data-plane padding.
    if name.contains("KEY_PAIR_GEN") {
        return (Some("pke"), None, None);
    }
    // Hash-prefixed `CKM_SHA256_RSA_PKCS` signs; bare `CKM_RSA_PKCS`
    // encrypts (observed operations disambiguate use).
    if name.contains("_RSA_PKCS") && name != "CKM_RSA_PKCS" {
        return (Some("signature"), None, Some("pkcs1v15"));
    }
    (Some("pke"), None, Some("pkcs1v15"))
}

fn block_cipher_of(
    name: &str,
) -> (
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
) {
    let primitive = if name.contains("_GCM") || name.contains("_CCM") || name.contains("_EAX") {
        "ae"
    } else {
        "block-cipher"
    };
    let mode = if name.contains("_GCM") {
        Some("gcm")
    } else if name.contains("_CCM") {
        Some("ccm")
    } else if name.contains("_CBC") {
        Some("cbc")
    } else if name.contains("_ECB") {
        Some("ecb")
    } else if name.contains("_CTR") {
        Some("ctr")
    } else if name.contains("_CFB") {
        Some("cfb")
    } else if name.contains("_OFB") {
        Some("ofb")
    } else if name.contains("_XTS")
        || name.contains("_CTS")
        || name.contains("_KW")
        || name.contains("_EAX")
        || name.contains("_OCB")
        || name.contains("_SIV")
    {
        Some("other")
    } else {
        None
    };
    let padding = if name.contains("_PAD") || name.contains("_PKCS") {
        Some("pkcs7")
    } else {
        None
    };
    (Some(primitive), mode, padding)
}

fn function_of(operation: &str) -> &'static str {
    match operation {
        "sign" | "sign_recover" | "message_sign" => "sign",
        "verify" | "verify_recover" | "message_verify" => "verify",
        "encrypt" | "message_encrypt" => "encrypt",
        "decrypt" | "message_decrypt" => "decrypt",
        "digest" => "digest",
        "generate_key" | "generate_key_pair" => "keygen",
        "wrap" | "wrap_authenticated" | "unwrap" | "unwrap_authenticated" => "other",
        "derive" => "keyderive",
        "encapsulate" => "encapsulate",
        "decapsulate" => "decapsulate",
        _ => "unknown",
    }
}
