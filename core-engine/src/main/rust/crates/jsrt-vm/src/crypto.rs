#![allow(dead_code)]

use jsrt_crypto::{aes128_ctr_crypt, constant_time_eq, hmac_sha256, sha256};

pub const DIGEST_SIZE: usize = 32;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKeyMaterial,
    KeyDerivationTooLarge,
    CiphertextTooLarge,
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; DIGEST_SIZE] {
    sha256(bytes).into_bytes()
}

pub(crate) fn hmac_bytes(key: &[u8], fields: &[&[u8]]) -> [u8; DIGEST_SIZE] {
    hmac_sha256(key, fields).into_bytes()
}

pub(crate) fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    constant_time_eq(left, right)
}

pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    if length > 255 * DIGEST_SIZE {
        return Err(CryptoError::KeyDerivationTooLarge);
    }
    let zero_salt = [0u8; DIGEST_SIZE];
    let extract_key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let mut prk = hmac_bytes(extract_key, &[ikm]);
    let mut output = Vec::with_capacity(length);
    let mut previous = [0u8; DIGEST_SIZE];
    let mut counter = 1u8;
    while output.len() < length {
        let block = hmac_bytes(&prk, &[&previous, info, &[counter]]);
        previous = block;
        let take = (length - output.len()).min(DIGEST_SIZE);
        output.extend_from_slice(&previous[..take]);
        counter = counter.wrapping_add(1);
    }
    prk.fill(0);
    previous.fill(0);
    Ok(output)
}

pub(crate) fn aes128_ctr(
    key: &[u8; 16],
    iv: &[u8; 16],
    input: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, CryptoError> {
    if input.len() > maximum {
        return Err(CryptoError::CiphertextTooLarge);
    }
    aes128_ctr_crypt(key, iv, input).map_err(|_| CryptoError::InvalidKeyMaterial)
}

pub(crate) fn vbc4_session_material(
    crypto_domain_material: &[u8; 32],
    layout_digest: &[u8; 32],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(21 + 32 + 32 + 4);
    material.extend_from_slice(b"vbc4-session-integrity");
    material.extend_from_slice(crypto_domain_material);
    material.extend_from_slice(layout_digest);
    material.extend_from_slice(&[0x10, 0x42, 0x9f, 0x6c]);
    let digest = sha256_bytes(&material);
    material.fill(0);
    digest
}

pub(crate) fn vbc4_hmac_fields(
    session_material: &[u8; 32],
    seed: u32,
    parts: &[&[u8]],
) -> [u8; 32] {
    let seed_bytes = seed.to_be_bytes();
    let mut fields = Vec::with_capacity(parts.len() + 1);
    fields.push(&seed_bytes[..]);
    fields.extend_from_slice(parts);
    let scoped = hmac_bytes(session_material, &fields);
    let output = hmac_bytes(&scoped, &fields);
    let mut scoped_wipe = scoped;
    scoped_wipe.fill(0);
    output
}

pub(crate) fn vbc4_hmac(
    session_material: &[u8; 32],
    seed: u32,
    parts: &[&[u8]],
    label: &[u8],
) -> [u8; 32] {
    let seed_bytes = seed.to_be_bytes();
    let mut fields = Vec::with_capacity(parts.len() + 2);
    fields.push(&seed_bytes[..]);
    fields.extend_from_slice(parts);
    fields.push(label);
    let scoped = hmac_bytes(session_material, &fields);
    let output = hmac_bytes(&scoped, &fields);
    let mut scoped_wipe = scoped;
    scoped_wipe.fill(0);
    output
}

pub(crate) fn vbc4_aes_material(
    session_material: &[u8; 32],
    nonce: &[u8; 16],
    seed: u32,
    section: u32,
    block_id: u32,
) -> ([u8; 16], [u8; 16]) {
    let section_bytes = section.to_be_bytes();
    let block_bytes = block_id.to_be_bytes();
    let parts = [&nonce[..], &section_bytes[..], &block_bytes[..]];
    let key_digest = vbc4_hmac(session_material, seed, &parts, b"vbc4-aes-key");
    let iv_digest = vbc4_hmac(session_material, seed, &parts, b"vbc4-aes-iv");
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&key_digest[..16]);
    iv.copy_from_slice(&iv_digest[..16]);
    let mut key_digest_wipe = key_digest;
    let mut iv_digest_wipe = iv_digest;
    key_digest_wipe.fill(0);
    iv_digest_wipe.fill(0);
    (key, iv)
}

pub(crate) fn vm_build_key(
    crypto_domain_material: &[u8; 32],
    layout_digest: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let derived = hkdf_sha256(
        crypto_domain_material,
        b"javashroud-vbc4-vm-build-key-v2",
        layout_digest,
        32,
    )?;
    let mut output = [0u8; 32];
    output.copy_from_slice(&derived);
    let mut wiped = derived;
    wiped.fill(0);
    Ok(output)
}

pub(crate) fn cp_string_material(
    build_key: &[u8; 32],
    key_label: &[u8],
    iv_label: &[u8],
    nonce: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    let key_digest = hmac_bytes(build_key, &[key_label, &nonce[..]]);
    let iv_digest = hmac_bytes(build_key, &[iv_label, &nonce[..]]);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&key_digest[..16]);
    iv.copy_from_slice(&iv_digest[..16]);
    (key, iv)
}

pub(crate) fn wipe_vec(bytes: &mut [u8]) {
    bytes.fill(0);
}

pub(crate) fn wipe_array<const N: usize>(bytes: &mut [u8; N]) {
    bytes.fill(0);
}

pub(crate) fn equal_tag(left: &[u8], right: &[u8]) -> bool {
    ct_eq(left, right)
}
