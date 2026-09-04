use crate::{PageError, PageKind, DIGEST_SIZE, ENCODED_HANDLE_SIZE, LOCATOR_TOKEN_SIZE};
use qp_crypto::{
    constant_time_eq, QpNameSchedule, Sha256, FORMAT_VERSION, LANE_DIR_RECORD, LANE_DIR_ROOT,
    LANE_RUNTIME_BINDING, QP_NAME_SEED_SIZE, QP_SCHEDULE_VERSION, ROLE_CRYPTO, ROLE_DIRECTORY,
};

pub const RETIRED_DIRECTORY_MAGIC: &[u8] = &[0x4a, 0x53, 0x52, 0x32, 0x44, 0x49, 0x52];
pub const PAGE_KEY_SIZE: usize = 1 + 4 + ENCODED_HANDLE_SIZE + LOCATOR_TOKEN_SIZE;
pub const MAX_DIRECTORY_ENTRIES: usize = 4096;
pub const MAX_DIRECTORY_SIZE: usize = 64 * 1024 * 1024;
pub const MAX_PATH_SIZE: usize = 4096;
pub const MAX_STORED_LENGTH: usize = 16 * 1024 * 1024 + 1024;
const MAX_TARGET_BYTES: usize = 64;
const MAX_PROFILE_BYTES: usize = 256;

pub const TEST_NAME_SEED: [u8; QP_NAME_SEED_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

const GCM_TAG_SIZE: usize = 16;
const SEALED_DIRECTORY_MAGIC: u8 = 0x6B;
const SEALED_DIRECTORY_VERSION: u8 = 1;
const SEALED_DIRECTORY_NONCE_SIZE: usize = 12;
const SEALED_DIRECTORY_DOMAIN: &[u8] = b"javashroud-qp-directory-v6";

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn sealed_directory_key(crypto_domain: &[u8; DIGEST_SIZE], name_seed: &[u8; QP_NAME_SEED_SIZE]) -> Result<[u8; DIGEST_SIZE], PageError> {
    let mut key = [0u8; DIGEST_SIZE];
    let derived = qp_crypto::hkdf_sha256(crypto_domain, SEALED_DIRECTORY_DOMAIN, name_seed, DIGEST_SIZE)
        .map_err(|_| PageError::InvalidInput("sealed directory key derivation failed"))?;
    key.copy_from_slice(&derived);
    Ok(key)
}

/// Seals a serialized directory: the records become one AES-256-GCM blob whose
/// key is derived from the pack's crypto domain, so page layout stays opaque
/// until the secret pack has been authorized in a live session.
pub fn seal_directory(
    plaintext: &[u8],
    name_seed: &[u8; QP_NAME_SEED_SIZE],
    crypto_domain: &[u8; DIGEST_SIZE],
    nonce: &[u8; SEALED_DIRECTORY_NONCE_SIZE],
) -> Result<Vec<u8>, PageError> {
    let key = sealed_directory_key(crypto_domain, name_seed)?;
    let mut header = Vec::with_capacity(4 + QP_NAME_SEED_SIZE + SEALED_DIRECTORY_NONCE_SIZE + 4);
    header.push(SEALED_DIRECTORY_MAGIC);
    header.push(SEALED_DIRECTORY_VERSION);
    header.push(0);
    header.push(0);
    header.extend_from_slice(name_seed);
    header.extend_from_slice(nonce);
    write_u32(&mut header, (plaintext.len() + GCM_TAG_SIZE) as u32);
    let sealed = qp_crypto::aes256_gcm_encrypt(&key, nonce, &header, plaintext)
        .map_err(|_| PageError::InvalidInput("sealed directory encryption failed"))?;
    let mut output = header;
    output.extend_from_slice(&sealed);
    Ok(output)
}

/// Returns the inner name seed, the shell-carried native SHA-256, and the
/// decrypted directory bytes; full parsing is left to [`decode_directory`] so
/// error semantics stay unchanged.
pub fn open_sealed_directory_parts(
    bytes: &[u8],
    crypto_domain: &[u8; DIGEST_SIZE],
) -> Result<([u8; QP_NAME_SEED_SIZE], [u8; DIGEST_SIZE], Vec<u8>), PageError> {
    const HEADER_SIZE: usize = 4 + QP_NAME_SEED_SIZE + SEALED_DIRECTORY_NONCE_SIZE + 4 + DIGEST_SIZE;
    if bytes.len() < HEADER_SIZE + GCM_TAG_SIZE {
        return Err(PageError::InvalidInput("sealed directory is truncated"));
    }
    if bytes[0] != SEALED_DIRECTORY_MAGIC || bytes[1] != SEALED_DIRECTORY_VERSION || bytes[2] != 0 || bytes[3] != 0 {
        return Err(PageError::InvalidInput("sealed directory header is invalid"));
    }
    let mut name_seed = [0u8; QP_NAME_SEED_SIZE];
    name_seed.copy_from_slice(&bytes[4..4 + QP_NAME_SEED_SIZE]);
    let blob_len = read_u32(bytes, 4 + QP_NAME_SEED_SIZE + SEALED_DIRECTORY_NONCE_SIZE) as usize;
    if bytes.len() != HEADER_SIZE + blob_len {
        return Err(PageError::InvalidInput("sealed directory length mismatch"));
    }
    let mut native_sha256 = [0u8; DIGEST_SIZE];
    native_sha256.copy_from_slice(&bytes[36..36 + DIGEST_SIZE]);
    let key = sealed_directory_key(crypto_domain, &name_seed)?;
    let plaintext = qp_crypto::aes256_gcm_decrypt(&key, &bytes[20..20 + SEALED_DIRECTORY_NONCE_SIZE], &bytes[..HEADER_SIZE], &bytes[HEADER_SIZE..])
        .map_err(|_| PageError::InvalidInput("sealed directory authentication failed"))?;
    Ok((name_seed, native_sha256, plaintext))
}

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
        Self::new_with_seed(
            artifact_commitment,
            native_sha256,
            abi_digest,
            target_triple,
            specialization_digest,
            payload_profile,
            &TEST_NAME_SEED,
        )
    }

    pub fn new_with_seed(
        artifact_commitment: [u8; DIGEST_SIZE],
        native_sha256: [u8; DIGEST_SIZE],
        abi_digest: [u8; DIGEST_SIZE],
        target_triple: &str,
        specialization_digest: [u8; DIGEST_SIZE],
        payload_profile: &str,
        name_seed: &[u8; QP_NAME_SEED_SIZE],
    ) -> Result<Self, PageError> {
        validate_target(target_triple)?;
        validate_profile(payload_profile)?;
        let schedule = QpNameSchedule::new(name_seed, &artifact_commitment, QP_SCHEDULE_VERSION)
            .map_err(|_| PageError::InvalidInput("name seed is invalid"))?;
        let domain = schedule
            .derive_domain(ROLE_CRYPTO, LANE_RUNTIME_BINDING, 0)
            .map_err(|_| PageError::InvalidInput("runtime domain derivation failed"))?;
        let digest = runtime_binding_digest(
            &domain,
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
    pub name_seed: [u8; QP_NAME_SEED_SIZE],
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
    let schedule = QpNameSchedule::new(
        &directory.name_seed,
        &directory.runtime.artifact_commitment,
        QP_SCHEDULE_VERSION,
    )
    .map_err(|_| PageError::InvalidInput("name seed is invalid"))?;
    let mut entries = directory.entries.clone();
    entries.sort_by_key(|entry| entry.key_bytes());
    for entry in &mut entries {
        entry.binding_digest = record_binding(
            &schedule
                .derive_domain(ROLE_DIRECTORY, LANE_DIR_RECORD, 0)
                .map_err(|_| PageError::InvalidInput("record domain derivation failed"))?,
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
    let magic = schedule
        .derive_magic(ROLE_DIRECTORY, 0, 0)
        .map_err(|_| PageError::InvalidInput("directory magic derivation failed"))?;
    output.push(FORMAT_VERSION);
    output.push(QP_SCHEDULE_VERSION);
    output.extend_from_slice(&directory.name_seed);
    output.extend_from_slice(&magic);
    write_u32(&mut output, entries.len() as u32);
    write_runtime(&mut output, &directory.runtime);
    let (blobs, blob_indices) = blob_table(&entries)?;
    write_u32(&mut output, blobs.len() as u32);
    for blob in &blobs {
        write_frame(&mut output, blob.as_bytes());
    }
    for (entry, blob_index) in entries.iter().zip(blob_indices.iter()) {
        write_entry(&mut output, entry, *blob_index)?;
    }
    let root_domain = schedule
        .derive_domain(ROLE_DIRECTORY, LANE_DIR_ROOT, 0)
        .map_err(|_| PageError::InvalidInput("root domain derivation failed"))?;
    let root = directory_root_digest(&root_domain, &directory.runtime, &entries);
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
    if bytes.len() >= RETIRED_DIRECTORY_MAGIC.len()
        && constant_time_eq(&bytes[..RETIRED_DIRECTORY_MAGIC.len()], RETIRED_DIRECTORY_MAGIC)
    {
        return Err(PageError::InvalidMagic);
    }
    let format_version = cursor.read_u8()?;
    if format_version != FORMAT_VERSION {
        return Err(PageError::InvalidMagic);
    }
    let schedule_version = cursor.read_u8()?;
    if schedule_version != QP_SCHEDULE_VERSION {
        return Err(PageError::InvalidMagic);
    }
    let name_seed = copy_fixed_array(&cursor.read_fixed(QP_NAME_SEED_SIZE)?)?;
    let claimed_magic = copy_fixed_array::<4>(&cursor.read_fixed(4)?)?;
    let count = cursor.read_u32_be()? as usize;
    if count > MAX_DIRECTORY_ENTRIES {
        return Err(PageError::LengthTooLarge {
            field: "directory entries",
            length: count,
            maximum: MAX_DIRECTORY_ENTRIES,
        });
    }
    let runtime = read_runtime(&mut cursor, &name_seed)?;
    let schedule = QpNameSchedule::new(
        &name_seed,
        &runtime.artifact_commitment,
        QP_SCHEDULE_VERSION,
    )
    .map_err(|_| PageError::InvalidInput("name seed is invalid"))?;
    let expected_magic = schedule
        .derive_magic(ROLE_DIRECTORY, 0, 0)
        .map_err(|_| PageError::InvalidInput("directory magic derivation failed"))?;
    if !constant_time_eq(&claimed_magic, &expected_magic) {
        return Err(PageError::AuthenticationFailed);
    }
    let record_domain = schedule
        .derive_domain(ROLE_DIRECTORY, LANE_DIR_RECORD, 0)
        .map_err(|_| PageError::InvalidInput("record domain derivation failed"))?;
    let root_domain = schedule
        .derive_domain(ROLE_DIRECTORY, LANE_DIR_ROOT, 0)
        .map_err(|_| PageError::InvalidInput("root domain derivation failed"))?;
    let blob_count = cursor.read_u32_be()? as usize;
    if blob_count > MAX_DIRECTORY_ENTRIES {
        return Err(PageError::LengthTooLarge {
            field: "directory path blobs",
            length: blob_count,
            maximum: MAX_DIRECTORY_ENTRIES,
        });
    }
    let mut blobs = Vec::with_capacity(blob_count);
    for _ in 0..blob_count {
        blobs.push(read_utf8_frame(&mut cursor, MAX_PATH_SIZE, "path blob")?);
    }
    let mut entries = Vec::with_capacity(count);
    let mut previous_key: Option<[u8; PAGE_KEY_SIZE]> = None;
    for _ in 0..count {
        let entry = read_entry(&mut cursor, &runtime, &record_domain, &blobs)?;
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
    let expected_root = directory_root_digest(&root_domain, &runtime, &entries);
    if !constant_time_eq(&supplied_root, &expected_root) {
        return Err(PageError::AuthenticationFailed);
    }
    Ok(ArtifactDirectory {
        runtime,
        entries,
        root_digest: expected_root,
        name_seed,
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

fn read_runtime(
    cursor: &mut crate::Cursor<'_>,
    name_seed: &[u8; QP_NAME_SEED_SIZE],
) -> Result<DirectoryRuntimeBinding, PageError> {
    let artifact = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let native = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let abi = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let target = read_ascii_frame(cursor, MAX_TARGET_BYTES, "target triple")?;
    let specialization = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let profile = read_ascii_frame(cursor, MAX_PROFILE_BYTES, "payload profile")?;
    let supplied = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let runtime = DirectoryRuntimeBinding::new_with_seed(
        artifact,
        native,
        abi,
        &target,
        specialization,
        &profile,
        name_seed,
    )?;
    if !constant_time_eq(&runtime.digest, &supplied) {
        return Err(PageError::AuthenticationFailed);
    }
    Ok(runtime)
}

fn write_entry(
    output: &mut Vec<u8>,
    entry: &ArtifactDirectoryEntry,
    blob_index: u16,
) -> Result<(), PageError> {
    validate_entry(entry)?;
    output.extend_from_slice(&entry.key_bytes());
    write_u16(output, blob_index);
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
    record_domain: &[u8],
    blobs: &[String],
) -> Result<ArtifactDirectoryEntry, PageError> {
    let key = cursor.read_fixed(PAGE_KEY_SIZE)?;
    let kind = PageKind::from_id(key[0])?;
    let page_index = i32::from_be_bytes(key[1..5].try_into().expect("page index"));
    if page_index < 0 {
        return Err(PageError::InvalidPageIndex(page_index));
    }
    let encoded_handle = copy_fixed_array(&key[5..5 + ENCODED_HANDLE_SIZE])?;
    let locator = copy_fixed_array(&key[5 + ENCODED_HANDLE_SIZE..])?;
    let blob_index = cursor.read_u16_be()? as usize;
    let relative_path = blobs
        .get(blob_index)
        .cloned()
        .ok_or(PageError::InvalidInput("directory path blob index is out of range"))?;
    let offset = cursor.read_i32_be()?;
    let stored_length = cursor.read_i32_be()?;
    let descriptor = cursor.read_frame(crate::MAX_DESCRIPTOR_ENCODING_SIZE, false, "descriptor")?;
    let envelope = cursor.read_frame(crate::MAX_ENVELOPE_SIZE, false, "envelope")?;
    let supplied_binding = copy_digest(&cursor.read_fixed(DIGEST_SIZE)?)?;
    let expected = record_binding(
        record_domain,
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
    domain: &[u8],
    artifact: &[u8; DIGEST_SIZE],
    native: &[u8; DIGEST_SIZE],
    abi: &[u8; DIGEST_SIZE],
    target: &str,
    specialization: &[u8; DIGEST_SIZE],
    profile: &str,
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
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
    domain: &[u8],
    runtime_digest: &[u8; DIGEST_SIZE],
    key: &[u8],
    path: &str,
    offset: i32,
    stored_length: i32,
    descriptor: &[u8],
    envelope: &[u8],
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
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
    domain: &[u8],
    runtime: &DirectoryRuntimeBinding,
    entries: &[ArtifactDirectoryEntry],
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
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

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn blob_table(entries: &[ArtifactDirectoryEntry]) -> Result<(Vec<String>, Vec<u16>), PageError> {
    let mut blobs = Vec::new();
    let mut indices = Vec::with_capacity(entries.len());
    for entry in entries {
        let index = match blobs.iter().position(|path| path == &entry.relative_path) {
            Some(existing) => existing,
            None => {
                blobs.push(entry.relative_path.clone());
                blobs.len() - 1
            }
        };
        let index = u16::try_from(index).map_err(|_| PageError::LengthTooLarge {
            field: "directory path blobs",
            length: index,
            maximum: u16::MAX as usize,
        })?;
        indices.push(index);
    }
    Ok((blobs, indices))
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
            "qp-rust-ffi-v1",
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
            name_seed: TEST_NAME_SEED,
        })
        .expect("encode");
        assert_eq!(encoded[0], FORMAT_VERSION);
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
            name_seed: TEST_NAME_SEED,
        })
        .expect("encode kotlin golden");
        assert_eq!(encoded[0], FORMAT_VERSION);
        assert_eq!(encoded[1], QP_SCHEDULE_VERSION);
        let decoded = decode_directory(&encoded).expect("decode kotlin golden");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].relative_path, "pages/page-0.bin");
        assert_eq!(decoded.name_seed, TEST_NAME_SEED);
    }

    #[test]
    fn retired_directory_magic_fails_closed() {
        let mut bytes = vec![0u8; 64];
        bytes[..RETIRED_DIRECTORY_MAGIC.len()].copy_from_slice(RETIRED_DIRECTORY_MAGIC);
        assert!(matches!(
            decode_directory(&bytes),
            Err(PageError::InvalidMagic)
        ));
    }


    #[test]
    fn unsupported_macos_target_fails_before_catalog_use() {
        assert!(DirectoryRuntimeBinding::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "x86_64-apple-darwin",
            [4; 32],
            "qp-rust-ffi-v1",
        )
        .is_err());
    }
}
