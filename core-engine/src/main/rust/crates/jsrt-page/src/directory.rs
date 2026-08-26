use crate::{PageError, PageKind, DIGEST_SIZE, ENCODED_HANDLE_SIZE, LOCATOR_TOKEN_SIZE};
use jsrt_crypto::{constant_time_eq, Sha256};

pub const DIRECTORY_MAGIC: &[u8; 7] = b"JSR2DIR";
pub const PAGE_KEY_SIZE: usize = 1 + 4 + ENCODED_HANDLE_SIZE + LOCATOR_TOKEN_SIZE;
pub const MAX_DIRECTORY_ENTRIES: usize = 4096;
pub const MAX_DIRECTORY_SIZE: usize = 64 * 1024 * 1024;
pub const MAX_PATH_SIZE: usize = 4096;
pub const MAX_STORED_LENGTH: usize = 16 * 1024 * 1024 + 1024;
const MAX_TARGET_BYTES: usize = 64;
const MAX_PROFILE_BYTES: usize = 256;

const RUNTIME_BINDING_DOMAIN: &[u8] = b"JavaShroud/AKEN-R2/ArtifactDirectory/RuntimeBindingDigest";
const RECORD_BINDING_DOMAIN: &[u8] = b"JavaShroud/AKEN-R2/ArtifactDirectory/RecordBinding";
const ROOT_BINDING_DOMAIN: &[u8] = b"JavaShroud/AKEN-R2/ArtifactDirectory/RootBinding";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRuntimeBinding {
    pub artifact_commitment: [u8; DIGEST_SIZE],
    pub native_sha256: [u8; DIGEST_SIZE],
    pub abi_digest: [u8; DIGEST_SIZE],
    pub target_triple: String,
    pub specialization_digest: [u8; DIGEST_SIZE],
    pub payload_profile: String,
    pub digest: [u8; DIGEST_SIZE],
}

impl DirectoryRuntimeBinding {
    pub fn new(
        artifact_commitment: [u8; DIGEST_SIZE],
        native_sha256: [u8; DIGEST_SIZE],
        abi_digest: [u8; DIGEST_SIZE],
        target_triple: &str,
        specialization_digest: [u8; DIGEST_SIZE],
        payload_profile: &str,
    ) -> Result<Self, PageError> {
        validate_target(target_triple)?;
        validate_profile(payload_profile)?;
        let digest = runtime_binding_digest(
            &artifact_commitment,
            &native_sha256,
            &abi_digest,
            target_triple,
            &specialization_digest,
            payload_profile,
        );
        Ok(Self {
            artifact_commitment,
            native_sha256,
            abi_digest,
            target_triple: target_triple.to_string(),
            specialization_digest,
            payload_profile: payload_profile.to_string(),
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDirectoryEntry {
    pub kind: PageKind,
    pub page_index: i32,
    pub encoded_handle: [u8; ENCODED_HANDLE_SIZE],
    pub locator: [u8; LOCATOR_TOKEN_SIZE],
    pub relative_path: String,
    pub offset: i32,
    pub stored_length: i32,
    pub descriptor: Vec<u8>,
    pub envelope: Vec<u8>,
    pub binding_digest: [u8; DIGEST_SIZE],
}

impl ArtifactDirectoryEntry {
    pub fn key_bytes(&self) -> [u8; PAGE_KEY_SIZE] {
        encode_page_key(
            self.kind,
            self.page_index,
            &self.encoded_handle,
            &self.locator,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDirectory {
    pub runtime: DirectoryRuntimeBinding,
    pub entries: Vec<ArtifactDirectoryEntry>,
    pub root_digest: [u8; DIGEST_SIZE],
}

impl ArtifactDirectory {
    pub fn encode(&self) -> Result<Vec<u8>, PageError> {
        encode_directory(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PageError> {
        decode_directory(bytes)
    }
}

pub fn encode_directory(directory: &ArtifactDirectory) -> Result<Vec<u8>, PageError> {
    if directory.entries.len() > MAX_DIRECTORY_ENTRIES {
        return Err(PageError::LengthTooLarge {
            field: "directory entries",
            length: directory.entries.len(),
            maximum: MAX_DIRECTORY_ENTRIES,
        });
    }
    let mut entries = directory.entries.clone();
    entries.sort_by_key(|entry| entry.key_bytes());
    for entry in &mut entries {
        entry.binding_digest = record_binding(
            &directory.runtime.digest,
            &entry.key_bytes(),
            &entry.relative_path,
            entry.offset,
            entry.stored_length,
            &entry.descriptor,
            &entry.envelope,
        );
    }
    let mut output = Vec::new();
    output.extend_from_slice(DIRECTORY_MAGIC);
    write_u32(&mut output, entries.len() as u32);
    write_runtime(&mut output, &directory.runtime);
    for entry in &entries {
        write_entry(&mut output, entry)?;
    }
    let root = directory_root_digest(&directory.runtime, &entries);
    output.extend_from_slice(&root);
    if output.len() > MAX_DIRECTORY_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "artifact directory",
            length: output.len(),
            maximum: MAX_DIRECTORY_SIZE,
        });
    }
    Ok(output)
}

pub fn decode_directory(bytes: &[u8]) -> Result<ArtifactDirectory, PageError> {
    if bytes.len() > MAX_DIRECTORY_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "artifact directory",
            length: bytes.len(),
            maximum: MAX_DIRECTORY_SIZE,
        });
    }
    let mut cursor = crate::Cursor::new(bytes);
    if cursor.read_fixed(DIRECTORY_MAGIC.len())?.as_slice() != DIRECTORY_MAGIC {
        return Err(PageError::InvalidMagic);
    }
    let count = cursor.read_u32_be()? as usize;
    if count > MAX_DIRECTORY_ENTRIES {
        return Err(PageError::LengthTooLarge {
            field: "directory entries",
            length: count,
            maximum: MAX_DIRECTORY_ENTRIES,
        });
    }
    let runtime = read_runtime(&mut cursor)?;
    let mut entries = Vec::with_capacity(count);
    let mut previous_key: Option<[u8; PAGE_KEY_SIZE]> = None;
    for _ in 0..count {
        let entry = read_entry(&mut cursor, &runtime)?;
        let key = entry.key_bytes();
        if let Some(previous) = previous_key {
            if key <= previous {
                return Err(PageError::BindingMismatch("directory entry order"));
            }
        }
        previous_key = Some(key);
        entries.push(entry);
    }
    let supplied_root = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    cursor.require_empty()?;
    let expected_root = directory_root_digest(&runtime, &entries);
    if !constant_time_eq(&supplied_root, &expected_root) {
        return Err(PageError::AuthenticationFailed);
    }
    Ok(ArtifactDirectory {
        runtime,
        entries,
        root_digest: expected_root,
    })
}

fn write_runtime(output: &mut Vec<u8>, runtime: &DirectoryRuntimeBinding) {
    output.extend_from_slice(&runtime.artifact_commitment);
    output.extend_from_slice(&runtime.native_sha256);
    output.extend_from_slice(&runtime.abi_digest);
    write_frame(output, runtime.target_triple.as_bytes());
    output.extend_from_slice(&runtime.specialization_digest);
    write_frame(output, runtime.payload_profile.as_bytes());
    output.extend_from_slice(&runtime.digest);
}

fn read_runtime(cursor: &mut crate::Cursor<'_>) -> Result<DirectoryRuntimeBinding, PageError> {
    let artifact = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let native = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let abi = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let target = read_ascii_frame(cursor, MAX_TARGET_BYTES, "target triple")?;
    let specialization = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let profile = read_ascii_frame(cursor, MAX_PROFILE_BYTES, "payload profile")?;
    let supplied = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let runtime =
        DirectoryRuntimeBinding::new(artifact, native, abi, &target, specialization, &profile)?;
    if !constant_time_eq(&runtime.digest, &supplied) {
        return Err(PageError::AuthenticationFailed);
    }
    Ok(runtime)
}

fn write_entry(output: &mut Vec<u8>, entry: &ArtifactDirectoryEntry) -> Result<(), PageError> {
    validate_entry(entry)?;
    output.extend_from_slice(&entry.key_bytes());
    write_frame(output, entry.relative_path.as_bytes());
    write_u32(output, entry.offset as u32);
    write_u32(output, entry.stored_length as u32);
    write_frame(output, &entry.descriptor);
    write_frame(output, &entry.envelope);
    output.extend_from_slice(&entry.binding_digest);
    Ok(())
}

fn read_entry(
    cursor: &mut crate::Cursor<'_>,
    runtime: &DirectoryRuntimeBinding,
) -> Result<ArtifactDirectoryEntry, PageError> {
    let key = cursor.read_fixed(PAGE_KEY_SIZE)?;
    let kind = PageKind::from_id(key[0])?;
    let page_index = i32::from_be_bytes(key[1..5].try_into().expect("page index"));
    if page_index < 0 {
        return Err(PageError::InvalidPageIndex(page_index));
    }
    let encoded_handle = copy_fixed_array(&key[5..5 + ENCODED_HANDLE_SIZE])?;
    let locator = copy_fixed_array(&key[5 + ENCODED_HANDLE_SIZE..])?;
    let relative_path = read_utf8_frame(cursor, MAX_PATH_SIZE, "relative path")?;
    let offset = cursor.read_i32_be()?;
    let stored_length = cursor.read_i32_be()?;
    let descriptor = cursor.read_frame(crate::MAX_DESCRIPTOR_ENCODING_SIZE, false, "descriptor")?;
    let envelope = cursor.read_frame(crate::MAX_ENVELOPE_SIZE, false, "envelope")?;
    let supplied_binding = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let expected = record_binding(
        &runtime.digest,
        &key,
        &relative_path,
        offset,
        stored_length,
        &descriptor,
        &envelope,
    );
    if !constant_time_eq(&supplied_binding, &expected) {
        return Err(PageError::AuthenticationFailed);
    }
    let entry = ArtifactDirectoryEntry {
        kind,
        page_index,
        encoded_handle,
        locator,
        relative_path,
        offset,
        stored_length,
        descriptor,
        envelope,
        binding_digest: expected,
    };
    validate_entry(&entry)?;
    Ok(entry)
}

fn validate_entry(entry: &ArtifactDirectoryEntry) -> Result<(), PageError> {
    if entry.relative_path.is_empty() || entry.relative_path.len() > MAX_PATH_SIZE {
        return Err(PageError::InvalidInput("directory path is invalid"));
    }
    if entry.offset < 0
        || entry.stored_length <= 0
        || entry.stored_length as usize > MAX_STORED_LENGTH
    {
        return Err(PageError::InvalidInput("directory stored range is invalid"));
    }
    if entry.descriptor.is_empty() || entry.envelope.is_empty() {
        return Err(PageError::InvalidInput(
            "directory record is missing page material",
        ));
    }
    Ok(())
}

fn runtime_binding_digest(
    artifact: &[u8; DIGEST_SIZE],
    native: &[u8; DIGEST_SIZE],
    abi: &[u8; DIGEST_SIZE],
    target: &str,
    specialization: &[u8; DIGEST_SIZE],
    profile: &str,
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(RUNTIME_BINDING_DOMAIN);
    update_runtime_canonical(
        &mut hasher,
        artifact,
        native,
        abi,
        target,
        specialization,
        profile,
    );
    *hasher.finalize().as_bytes()
}

fn record_binding(
    runtime_digest: &[u8; DIGEST_SIZE],
    key: &[u8],
    path: &str,
    offset: i32,
    stored_length: i32,
    descriptor: &[u8],
    envelope: &[u8],
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_BINDING_DOMAIN);
    hasher.update(runtime_digest);
    hasher.update(key);
    update_framed(&mut hasher, path.as_bytes());
    update_i32(&mut hasher, offset);
    update_i32(&mut hasher, stored_length);
    update_framed(&mut hasher, descriptor);
    update_framed(&mut hasher, envelope);
    *hasher.finalize().as_bytes()
}

fn directory_root_digest(
    runtime: &DirectoryRuntimeBinding,
    entries: &[ArtifactDirectoryEntry],
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_BINDING_DOMAIN);
    update_u32(&mut hasher, entries.len() as u32);
    update_runtime_canonical(
        &mut hasher,
        &runtime.artifact_commitment,
        &runtime.native_sha256,
        &runtime.abi_digest,
        &runtime.target_triple,
        &runtime.specialization_digest,
        &runtime.payload_profile,
    );
    hasher.update(&runtime.digest);
    for entry in entries {
        hasher.update(&entry.key_bytes());
        update_framed(&mut hasher, entry.relative_path.as_bytes());
        update_i32(&mut hasher, entry.offset);
        update_i32(&mut hasher, entry.stored_length);
        update_framed(&mut hasher, &entry.descriptor);
        update_framed(&mut hasher, &entry.envelope);
        hasher.update(&entry.binding_digest);
    }
    *hasher.finalize().as_bytes()
}

fn update_runtime_canonical(
    hasher: &mut Sha256,
    artifact: &[u8; DIGEST_SIZE],
    native: &[u8; DIGEST_SIZE],
    abi: &[u8; DIGEST_SIZE],
    target: &str,
    specialization: &[u8; DIGEST_SIZE],
    profile: &str,
) {
    hasher.update(artifact);
    hasher.update(native);
    hasher.update(abi);
    update_framed(hasher, target.as_bytes());
    hasher.update(specialization);
    update_framed(hasher, profile.as_bytes());
}

fn update_framed(hasher: &mut Sha256, value: &[u8]) {
    update_u32(hasher, value.len() as u32);
    hasher.update(value);
}

fn update_i32(hasher: &mut Sha256, value: i32) {
    update_u32(hasher, value as u32);
}

fn update_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_frame(output: &mut Vec<u8>, value: &[u8]) {
    write_u32(output, value.len() as u32);
    output.extend_from_slice(value);
}

fn read_ascii_frame(
    cursor: &mut crate::Cursor<'_>,
    maximum: usize,
    field: &'static str,
) -> Result<String, PageError> {
    let bytes = cursor.read_frame(maximum, false, field)?;
    if bytes.is_empty() || !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err(PageError::InvalidInput(field));
    }
    String::from_utf8(bytes).map_err(|_| PageError::InvalidInput(field))
}

fn read_utf8_frame(
    cursor: &mut crate::Cursor<'_>,
    maximum: usize,
    field: &'static str,
) -> Result<String, PageError> {
    let bytes = cursor.read_frame(maximum, false, field)?;
    String::from_utf8(bytes).map_err(|_| PageError::InvalidInput(field))
}

fn encode_page_key(
    kind: PageKind,
    page_index: i32,
    encoded_handle: &[u8; ENCODED_HANDLE_SIZE],
    locator: &[u8; LOCATOR_TOKEN_SIZE],
) -> [u8; PAGE_KEY_SIZE] {
    let mut key = [0u8; PAGE_KEY_SIZE];
    key[0] = kind.id();
    key[1..5].copy_from_slice(&page_index.to_be_bytes());
    key[5..5 + ENCODED_HANDLE_SIZE].copy_from_slice(encoded_handle);
    key[5 + ENCODED_HANDLE_SIZE..].copy_from_slice(locator);
    key
}

fn copy_digest(bytes: &[u8]) -> Result<[u8; DIGEST_SIZE], PageError> {
    copy_fixed_array(bytes)
}

fn copy_fixed_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PageError> {
    bytes.try_into().map_err(|_| PageError::InvalidLength {
        field: "fixed digest",
        expected: N,
        actual: bytes.len(),
    })
}

fn validate_target(target: &str) -> Result<(), PageError> {
    if target != "x86_64-pc-windows-gnu" && target != "x86_64-unknown-linux-gnu.2.17" {
        return Err(PageError::UnsupportedVersion(0));
    }
    Ok(())
}

fn validate_profile(profile: &str) -> Result<(), PageError> {
    if profile.is_empty()
        || profile.len() > MAX_PROFILE_BYTES
        || !profile.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(PageError::InvalidInput("payload profile"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_runtime() -> DirectoryRuntimeBinding {
        DirectoryRuntimeBinding::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "x86_64-pc-windows-gnu",
            [4; 32],
            "aken-r1-rust-ffi-v1",
        )
        .expect("runtime")
    }

    fn sample_entry(index: i32) -> ArtifactDirectoryEntry {
        let runtime = sample_runtime();
        let mut entry = ArtifactDirectoryEntry {
            kind: PageKind::StringPage,
            page_index: index,
            encoded_handle: [index as u8; ENCODED_HANDLE_SIZE],
            locator: [0xA0 + index as u8; LOCATOR_TOKEN_SIZE],
            relative_path: format!("pages/page-{index}.bin"),
            offset: 17 + index,
            stored_length: 99 + index,
            descriptor: vec![1, 2, 3, index as u8],
            envelope: vec![9, 8, 7, index as u8],
            binding_digest: [0; DIGEST_SIZE],
        };
        entry.binding_digest = record_binding(
            &runtime.digest,
            &entry.key_bytes(),
            &entry.relative_path,
            entry.offset,
            entry.stored_length,
            &entry.descriptor,
            &entry.envelope,
        );
        entry
    }

    #[test]
    fn directory_round_trip_authenticates_and_rejects_tampering() {
        let runtime = sample_runtime();
        let entries = vec![sample_entry(0), sample_entry(2), sample_entry(1)];
        let encoded = encode_directory(&ArtifactDirectory {
            runtime: runtime.clone(),
            entries: entries.clone(),
            root_digest: [0; DIGEST_SIZE],
        })
        .expect("encode");
        assert!(encoded.starts_with(DIRECTORY_MAGIC));
        let decoded = decode_directory(&encoded).expect("decode");
        assert_eq!(decoded.runtime.digest, runtime.digest);
        assert_eq!(decoded.entries.len(), 3);
        assert!(decoded
            .entries
            .windows(2)
            .all(|pair| pair[0].key_bytes() < pair[1].key_bytes()));

        let mut tampered = encoded.clone();
        *tampered.last_mut().expect("root") ^= 1;
        assert!(matches!(
            decode_directory(&tampered),
            Err(PageError::AuthenticationFailed)
        ));
    }

    fn kotlin_golden_runtime() -> DirectoryRuntimeBinding {
        DirectoryRuntimeBinding::new(
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| (i + 32) as u8),
            core::array::from_fn(|i| (i + 64) as u8),
            "x86_64-pc-windows-gnu",
            core::array::from_fn(|i| (i + 96) as u8),
            "golden-profile",
        )
        .expect("kotlin golden runtime")
    }

    fn kotlin_golden_page() -> ArtifactDirectoryEntry {
        let encoded_handle = core::array::from_fn(|i| i as u8);
        let locator = core::array::from_fn(|i| 0xA0 + i as u8);
        ArtifactDirectoryEntry {
            kind: PageKind::StringPage,
            page_index: 0,
            encoded_handle,
            locator,
            relative_path: "pages/page-0.bin".to_string(),
            offset: 17,
            stored_length: 99,
            descriptor: vec![1, 2, 3, 0],
            envelope: vec![9, 8, 7, 0],
            binding_digest: [0; DIGEST_SIZE],
        }
    }

    #[test]
    fn kotlin_golden_directory_round_trips() {
        let encoded = encode_directory(&ArtifactDirectory {
            runtime: kotlin_golden_runtime(),
            entries: vec![kotlin_golden_page()],
            root_digest: [0; DIGEST_SIZE],
        })
        .expect("encode kotlin golden");
        assert!(encoded.starts_with(DIRECTORY_MAGIC));
        let decoded = decode_directory(&encoded).expect("decode kotlin golden");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].relative_path, "pages/page-0.bin");
        let mut hex = String::with_capacity(encoded.len() * 2);
        for byte in &encoded {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        assert_eq!(hex, KOTLIN_GOLDEN_HEX);
    }

    const KOTLIN_GOLDEN_HEX: &str = "4a53523144495200000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000157838365f36342d70632d77696e646f77732d676e75606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000e676f6c64656e2d70726f66696c65641e4457e0214b7f2a7c28cb37615df8b0d76ca12c61cccfb3b58eb7a07706200200000000000102030405060708090a0b0c0d0e0f1011121314151617a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0000001070616765732f706167652d302e62696e000000110000006300000004010203000000000409080700503a3ce9d1dae1566b4f130472b3f162c96c3ae92582e0bc767022cfde7419c4e34db6d8067cc0808989f0afc16da7014d1be887737353bbf0affcd56c4dc3cd";

    #[test]
    fn unsupported_macos_target_fails_before_catalog_use() {
        assert!(DirectoryRuntimeBinding::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "x86_64-apple-darwin",
            [4; 32],
            "aken-r1-rust-ffi-v1",
        )
        .is_err());
    }
}
