use jsrt_crypto::sha256;
use std::collections::BTreeMap;

pub const ORIGINAL_HELPER_OWNER: &str =
    "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper";

pub const TYPED_R1_METHODS: [(&str, &str); 7] = [
    ("nativeInit", "(Ljava/lang/String;)I"),
    ("nativeHeartbeat", "()I"),
    ("nativeInstallAkenSessionNonce", "([B)Z"),
    (
        "nativeExecuteAkenVmPage",
        "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
    ),
    ("nativeOpenAkenString", "([BI[B)Ljava/lang/String;"),
    ("nativeReadAkenClassPage", "([BI[B)[B"),
    ("nativeConsumeAkenNativeChunk", "([BI[B)V"),
];

const BINDING_DOMAIN: &[u8] = b"AKEN-BINDING-V1|";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationPlan {
    pub owner: String,
    pub methods: [(String, &'static str); 7],
}

pub fn sealed_binding_key(value: &str) -> String {
    let mut encoded = Vec::with_capacity(BINDING_DOMAIN.len() + value.len());
    encoded.extend_from_slice(BINDING_DOMAIN);
    encoded.extend_from_slice(value.as_bytes());
    let digest = sha256(&encoded);
    encoded.fill(0);
    hex_lower(&digest.as_bytes()[..8])
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
            .ok_or("AKEN-R1 method binding line is malformed")?;
        let key = line[..separator].to_string();
        let value = line[separator + 1..].to_string();
        if key.is_empty() || value.is_empty() || value.contains('\0') {
            return Err("AKEN-R1 method binding value is invalid");
        }
        map.insert(key, value);
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
        return Err("AKEN-R1 helper owner is invalid");
    }
    let methods = TYPED_R1_METHODS.map(|(name, signature)| {
        let key = sealed_binding_key(&format!("{ORIGINAL_HELPER_OWNER}#{name}#{signature}"));
        let remapped = method_bindings
            .get(&key)
            .cloned()
            .unwrap_or_else(|| name.to_string());
        (remapped, signature)
    });
    let mut seen = BTreeMap::new();
    for (name, signature) in &methods {
        if name.is_empty() || name.contains('\0') || name.len() > 256 {
            return Err("AKEN-R1 remapped JNI method name is invalid");
        }
        if seen.insert((name.as_str(), *signature), ()).is_some() {
            return Err("AKEN-R1 remapped JNI method names are not unique");
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
    fn sealed_binding_key_matches_the_aken_v1_domain() {
        assert_eq!(
            sealed_binding_key(ORIGINAL_HELPER_OWNER),
            "3a7c2b4b146de48d"
        );
        assert_ne!(
            sealed_binding_key(ORIGINAL_HELPER_OWNER),
            sealed_binding_key("other/Helper")
        );
    }

    #[test]
    fn missing_bindings_keep_the_source_helper_surface() {
        let plan = resolve_registration(None, &BTreeMap::new()).expect("plan");
        assert_eq!(plan.owner, ORIGINAL_HELPER_OWNER);
        assert_eq!(
            plan.methods.map(|(name, signature)| (name, signature)),
            TYPED_R1_METHODS.map(|(name, signature)| (name.to_string(), signature))
        );
    }

    #[test]
    fn published_loader_and_method_bindings_restore_the_renamed_surface() {
        let native_init_key = sealed_binding_key(&format!(
            "{ORIGINAL_HELPER_OWNER}#nativeInit#(Ljava/lang/String;)I"
        ));
        let mut methods = BTreeMap::new();
        methods.insert(native_init_key, "m_init".to_string());
        let plan = resolve_registration(Some("a/b/SealedHelper"), &methods).expect("plan");
        assert_eq!(plan.owner, "a/b/SealedHelper");
        assert_eq!(plan.methods[0].0, "m_init");
        assert_eq!(plan.methods[1].0, "nativeHeartbeat");
    }
}
