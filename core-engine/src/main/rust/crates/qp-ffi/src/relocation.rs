use qp_crypto::sha256;
use std::collections::BTreeMap;

pub const ORIGINAL_HELPER_OWNER: &str =
    "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge";

pub const TYPED_NATIVE_METHOD_COUNT: usize = 15;
pub const TYPED_NATIVE_METHODS: [(&str, &str); TYPED_NATIVE_METHOD_COUNT] = [
    ("nativeInit", "(Ljava/lang/String;)I"),
    ("nativeHeartbeat", "()I"),
    ("nativeInstallSessionNonce", "([B)Z"),
    ("nativeInstallCatalog", "([B[B[B)I"),
    (
        "nativeExecuteVmPage",
        "(J[B[Ljava/lang/Object;)Ljava/lang/Object;",
    ),
    ("nativeOpenStringPage", "([B)Ljava/lang/String;"),
    ("nativeReadClassPage", "([B)[B"),
    ("nativeConsumeNativeSegment", "([B)V"),
    (
        "nativeInitializeDefense",
        "(Ljava/lang/String;Ljava/lang/String;)I",
    ),
    (
        "nativeProbeDefense",
        "(Ljava/lang/String;Ljava/lang/String;)I",
    ),
    ("nativeTransformDefense", "([BLjava/lang/String;)[B"),
    (
        "nativeInvokeSite",
        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[B[Ljava/lang/Object;Z)Ljava/lang/Object;",
    ),
    ("nativeInitializeDefenseCode", "(II)I"),
    ("nativeProbeDefenseCode", "(II)I"),
    ("nativeTransformDefenseCode", "([BI)[B"),
];

const BINDING_DOMAIN: &[u8] = b"QP-BINDING-V1|";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationPlan {
    pub owner: String,
    pub methods: [(String, &'static str); TYPED_NATIVE_METHOD_COUNT],
}

pub fn sealed_binding_key(value: &str) -> String {
    let mut encoded = Vec::with_capacity(BINDING_DOMAIN.len() + value.len());
    encoded.extend_from_slice(BINDING_DOMAIN);
    encoded.extend_from_slice(value.as_bytes());
    let digest = sha256(&encoded);
    encoded.fill(0);
    hex_lower(&digest.as_bytes()[..8])
}

const SEALED_BINDINGS_DOMAIN: &[u8] = b"javashroud-qp-bindings-v6";
const SEALED_BINDINGS_NONCE: usize = 12;

/// Decrypts the sealed relocation-binding resource: `nonce(12) || ct||tag`,
/// AES-256-GCM under `HKDF(cryptoDomain, "javashroud-qp-bindings-v6")` with
/// the domain as AAD. Only the native runtime holds the key material.
pub fn decrypt_sealed_bindings(
    crypto_domain: &[u8; 32],
    sealed: &[u8],
) -> Result<String, &'static str> {
    use qp_crypto::{aes256_gcm_decrypt, hkdf_sha256};
    if sealed.len() < SEALED_BINDINGS_NONCE + 16 {
        return Err("Qp sealed bindings are truncated");
    }
    let key = hkdf_sha256(crypto_domain, SEALED_BINDINGS_DOMAIN, &[], 32)
        .map_err(|_| "Qp sealed bindings key derivation failed")?;
    let plaintext = aes256_gcm_decrypt(
        &key,
        &sealed[..SEALED_BINDINGS_NONCE],
        SEALED_BINDINGS_DOMAIN,
        &sealed[SEALED_BINDINGS_NONCE..],
    )
    .map_err(|_| "Qp sealed bindings authentication failed")?;
    String::from_utf8(plaintext).map_err(|_| "Qp sealed bindings plaintext is invalid")
}

/// Extracts the method-binding map from the full B|M|F relocation text.
pub fn method_binding_map(binding_text: &str) -> Result<BTreeMap<String, String>, &'static str> {
    let mut method_lines = String::with_capacity(binding_text.len());
    for raw in binding_text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("M|") {
            // Records are pipe-framed (`M|key|value`); the map form is `key=value`.
            if let Some(separator) = rest.find('|') {
                if !method_lines.is_empty() {
                    method_lines.push('\n');
                }
                method_lines.push_str(&rest[..separator]);
                method_lines.push('=');
                method_lines.push_str(&rest[separator + 1..]);
            }
        }
    }
    parse_binding_map(&method_lines)
}

/// Decodes the URL-alphabet, unpadded base64 used by the bootstrap properties.
pub fn base64_url_decode(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let remainder = bytes.len() % 4;
    if remainder == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    let full = &bytes[..bytes.len() - remainder];
    for chunk in full.chunks(4) {
        let mut group = 0u32;
        for byte in chunk {
            group = (group << 6) | value(*byte)?;
        }
        out.push((group >> 16) as u8);
        out.push((group >> 8) as u8);
        out.push(group as u8);
    }
    if remainder > 0 {
        let mut group = 0u32;
        for byte in &bytes[bytes.len() - remainder..] {
            group = (group << 6) | value(*byte)?;
        }
        group <<= 6 * (4 - remainder);
        out.push((group >> 16) as u8);
        if remainder == 3 {
            out.push((group >> 8) as u8);
        }
    }
    Some(out)
}

pub fn parse_binding_map(text: &str) -> Result<BTreeMap<String, String>, &'static str> {
    let mut map = BTreeMap::new();
    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let separator = line
            .find('=')
            .filter(|index| *index > 0)
            .ok_or("Qp method binding line is malformed")?;
        let key = line[..separator].to_string();
        let value = line[separator + 1..].to_string();
        if key.is_empty() || value.is_empty() || value.contains('\0') {
            return Err("Qp method binding value is invalid");
        }
        if map.insert(key, value).is_some() {
            return Err("Qp method binding map has duplicate keys");
        }
    }
    Ok(map)
}

pub fn resolve_registration(
    loader_owner: Option<&str>,
    method_bindings: &BTreeMap<String, String>,
) -> Result<RegistrationPlan, &'static str> {
    let owner = loader_owner
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(ORIGINAL_HELPER_OWNER);
    if owner.contains('\0') || owner.len() > 512 {
        return Err("Qp helper owner is invalid");
    }
    let relocated_owner = owner != ORIGINAL_HELPER_OWNER;
    let methods = TYPED_NATIVE_METHODS.map(|(name, signature)| {
        let key = sealed_binding_key(&format!("{ORIGINAL_HELPER_OWNER}#{name}#{signature}"));
        let remapped = match method_bindings.get(&key) {
            Some(value) => value.clone(),
            None if !relocated_owner => name.to_string(),
            None => return Err("Qp sealed JNI binding map is incomplete"),
        };
        Ok((remapped, signature))
    });
    let methods: [(String, &'static str); TYPED_NATIVE_METHOD_COUNT] = methods
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error)?
        .try_into()
        .map_err(|_| "Qp typed JNI registration shape is invalid")?;
    let mut seen = BTreeMap::new();
    for (name, signature) in &methods {
        if name.is_empty() || name.contains('\0') || name.len() > 256 {
            return Err("Qp remapped JNI method name is invalid");
        }
        if seen.insert((name.as_str(), *signature), ()).is_some() {
            return Err("Qp remapped JNI method names are not unique");
        }
    }
    Ok(RegistrationPlan {
        owner: owner.to_string(),
        methods,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_binding_key_is_domain_separated() {
        let key = sealed_binding_key(ORIGINAL_HELPER_OWNER);
        assert_eq!(key.len(), 16);
        assert_ne!(key, "fc4a54928d08f1f1");
        assert_ne!(key, sealed_binding_key("other/Helper"));
    }

    #[test]
    fn missing_bindings_keep_the_source_helper_surface_only() {
        let plan = resolve_registration(None, &BTreeMap::new()).expect("plan");
        assert_eq!(plan.owner, ORIGINAL_HELPER_OWNER);
        assert_eq!(
            plan.methods.map(|(name, signature)| (name, signature)),
            TYPED_NATIVE_METHODS.map(|(name, signature)| (name.to_string(), signature))
        );
    }

    #[test]
    fn relocated_owner_requires_every_typed_binding() {
        let error = resolve_registration(Some("a/b/SealedHelper"), &BTreeMap::new())
            .expect_err("relocated owner must fail closed without bindings");
        assert_eq!(error, "Qp sealed JNI binding map is incomplete");
    }

    #[test]
    fn published_loader_and_method_bindings_restore_the_complete_renamed_surface() {
        let mut methods = BTreeMap::new();
        for (index, (name, signature)) in TYPED_NATIVE_METHODS.iter().enumerate() {
            methods.insert(
                sealed_binding_key(&format!("{ORIGINAL_HELPER_OWNER}#{name}#{signature}")),
                format!("m_{index}"),
            );
        }
        let plan = resolve_registration(Some("a/b/SealedHelper"), &methods).expect("plan");
        assert_eq!(plan.owner, "a/b/SealedHelper");
        assert_eq!(plan.methods[0].0, "m_0");
        assert_eq!(plan.methods[TYPED_NATIVE_METHOD_COUNT - 1].0, "m_14");
    }
}

#[cfg(test)]
mod sealed_tests {
    use super::*;
    use qp_crypto::{aes256_gcm_encrypt, hkdf_sha256};

    #[test]
    fn sealed_bindings_round_trip_and_m_filter() {
        let domain = b"javashroud-qp-bindings-v6";
        let crypto_domain = [0x5Au8; 32];
        let plain = "B|k1|v1\nM|abc|renamed\nF|k2|v2\n";
        let key = hkdf_sha256(&crypto_domain, domain, &[], 32).expect("key");
        let nonce = [0x11u8; 12];
        let sealed = aes256_gcm_encrypt(&key, &nonce, domain, plain.as_bytes()).expect("seal");
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        let opened = decrypt_sealed_bindings(&crypto_domain, &blob).expect("open");
        let map = method_binding_map(&opened).expect("map");
        assert_eq!(map.get("abc").map(String::as_str), Some("renamed"));
        assert_eq!(map.len(), 1);
        let mut wrong = crypto_domain;
        wrong[0] ^= 1;
        assert!(decrypt_sealed_bindings(&wrong, &blob).is_err());
    }

    #[test]
    fn base64_url_decode_matches_java_url_encoder() {
        assert_eq!(base64_url_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(base64_url_decode("aGVsbG8h"), Some(b"hello!".to_vec()));
        assert_eq!(base64_url_decode("-_8"), Some(vec![0xFB, 0xFF]));
        assert_eq!(base64_url_decode("a"), None);
        assert_eq!(base64_url_decode("a+b/"), None);
    }
}
