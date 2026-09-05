//! Per-artifact native secret pack (v6, sharded).
//!
//! The sealed pack travels as authenticated catalog data, never as a native
//! source constant. It is split into independently wrapped shards — one root
//! shard (identity, crypto domain, layout digest) and one shard per resource
//! kind — so compromising one shard does not expose the others. Each shard key
//! is `HMAC(reconstruct_shard_key, image commitment)`; the commitment lives in
//! the `.jsms` slot and is read at runtime only, so the shard keys can never
//! be constant-folded into a contiguous static window.

use crate::image_measure;
use crate::specialization;
use qp_crypto::{aes256_gcm_decrypt, constant_time_eq, hmac_sha256_bytes, hkdf_sha256};
use qp_runtime::{PageKeyAuthority, PageKeyMaterial, PageKeyRequest, RouterError};
use std::sync::Mutex;

const PAGE_KEY_DOMAIN: &[u8] = b"javashroud-qp-page-key-v6";
const COMMITMENT_DOMAIN: &[u8] = b"javashroud-qp-secret-commitment-v6";
/// Domain label for wrap AAD derivation. Packed under a non-foldable mask so
/// the ASCII string is not a contiguous `.rdata` literal a scanner can grep.
#[inline(never)]
fn wrap_aad_info() -> [u8; 28] {
    let packed: [u8; 28] = [
        0x3F, 0x34, 0x23, 0x34, 0x26, 0x3D, 0x27, 0x3A, 0x20, 0x31, 0x78, 0x24, 0x25, 0x78,
        0x26, 0x30, 0x36, 0x27, 0x30, 0x21, 0x78, 0x22, 0x27, 0x34, 0x25, 0x78, 0x23, 0x63,
    ];
    let mut info = [0u8; 28];
    for index in 0..28 {
        info[index] = packed[index] ^ 0x55;
    }
    // Volatile read keeps LLVM from reconstituting the ASCII into .rdata.
    unsafe { core::ptr::read_volatile(&info) }
}
const SHARD_KIND_ROOT: u8 = 0;
const ENTRY_TOKEN_DOMAIN: &[u8] = b"javashroud-qp-entry-token-v6";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

struct Recombined {
    /// Seeds indexed by kind id (`QpResourceKind`), each slot list indexed by
    /// slot id within that kind.
    kinds: Vec<Vec<Option<[u8; KEY_SIZE]>>>,
    crypto_domain: [u8; KEY_SIZE],
    layout_digest: [u8; KEY_SIZE],
}

impl Drop for Recombined {
    fn drop(&mut self) {
        for kind in &mut self.kinds {
            for seed in kind.iter_mut().flatten() {
                seed.fill(0);
            }
        }
        self.crypto_domain.fill(0);
        self.layout_digest.fill(0);
    }
}

/// Per-build wrap AAD: SHA-256(nativeIdentity || domain). The ASCII domain
/// never appears as a searchable label in the compiled image.
fn wrap_aad() -> [u8; 32] {
    let identity = specialization::SECRET_PACK_NATIVE_IDENTITY;
    let info = wrap_aad_info();
    let mut input = [0u8; 32 + 28];
    input[..32].copy_from_slice(&identity);
    input[32..].copy_from_slice(&info);
    let derived = qp_crypto::sha256(&input).into_bytes();
    input.fill(0);
    derived
}

/// Artifact-specific secret authority backed by the generated specialization.
pub struct SecretPackState {
    native_identity: [u8; KEY_SIZE],
    state: Mutex<Option<Recombined>>,
}

impl SecretPackState {
    /// Builds the authority from the generated specialization constants. The
    /// pack stays sealed until [`SecretPackState::authorize`] succeeds.
    pub fn from_specialization() -> Self {
        Self {
            native_identity: specialization::SECRET_PACK_NATIVE_IDENTITY,
            state: Mutex::new(None),
        }
    }

    /// Unwraps every shard exactly once. The sealed pack arrives as catalog
    /// data; each shard key mixes the runtime-read image commitment, so the
    /// unwrap can never be evaluated offline from native constants alone.
    /// Measurement mismatch, a missing session, or a truncated shard keeps
    /// the pack sealed.
    pub fn authorize(
        &self,
        authorized: bool,
        session_armed: bool,
        sealed_pack: &[u8],
    ) -> Result<(), RouterError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        if guard.is_some() {
            return Ok(());
        }
        if !authorized || !session_armed {
            return Err(RouterError::InvalidRequest("secret pack session is missing"));
        }
        if sealed_pack.is_empty() {
            return Err(RouterError::InvalidRequest("secret wrap is empty"));
        }
        if specialization::SECRET_PACK_SHARD_COUNT == 0 {
            return Err(RouterError::InvalidRequest("secret wrap is empty"));
        }
        let commitment = specialization::image_measurement_commitment();
        // The measurement commitment stays a pure file-integrity oracle for the
        // measurement shard's static half; it can confirm a guessed key but no
        // longer decrypts anything by itself.
        let mut measurement_key = specialization::qp_sp_reconstruct_shard_key(1);
        if measurement_key == [0u8; KEY_SIZE] {
            return Err(RouterError::InvalidRequest("secret wrap key is zero"));
        }
        if image_measure::verify_wrap_key(&measurement_key).is_err() {
            measurement_key.fill(0);
            return Err(RouterError::InvalidRequest("secret image measurement failed"));
        }
        measurement_key.fill(0);
        let shards = parse_sealed_pack(sealed_pack)
            .map_err(|_| RouterError::InvalidRequest("secret wrap container is invalid"))?;
        if shards.len() != specialization::SECRET_PACK_SHARD_COUNT {
            return Err(RouterError::InvalidRequest("secret wrap shard count mismatch"));
        }
        let mut kinds: Vec<Vec<Option<[u8; KEY_SIZE]>>> =
            vec![Vec::new(); specialization::SECRET_PACK_KIND_COUNT];
        let mut root: Option<([u8; KEY_SIZE], [u8; KEY_SIZE], usize)> = None;
        for (index, shard) in shards.iter().enumerate() {
            let (kind, nonce, wrapped) = shard;
            let mut static_key = specialization::qp_sp_reconstruct_shard_key(index);
            if static_key == [0u8; KEY_SIZE] {
                static_key.fill(0);
                return Err(RouterError::InvalidRequest("secret wrap key is zero"));
            }
            let shard_key = hmac_sha256_bytes(&static_key, &[&commitment]);
            static_key.fill(0);
            let wrap_aad = wrap_aad();
            let plaintext = match aes256_gcm_decrypt(&shard_key, nonce, &wrap_aad, wrapped) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(RouterError::InvalidRequest("secret wrap decrypt failed"));
                }
            };
            let parsed = parse_shard(&plaintext, *kind, &mut kinds, &mut root, &self.native_identity);
            let mut owned = plaintext;
            owned.fill(0);
            parsed.map_err(|_| RouterError::InvalidRequest("secret wrap plaintext is invalid"))?;
        }
        let (_, _, total_slots) = root.ok_or(RouterError::InvalidRequest(
            "secret wrap plaintext is invalid",
        ))?;
        let armed: usize = kinds
            .iter()
            .map(|kind| kind.iter().flatten().count())
            .sum();
        if armed != total_slots {
            return Err(RouterError::InvalidRequest(
                "secret wrap plaintext is invalid",
            ));
        }
        let (crypto_domain, layout_digest, _) = root.ok_or(RouterError::AuthenticationFailed)?;
        *guard = Some(Recombined {
            kinds,
            crypto_domain,
            layout_digest,
        });
        Ok(())
    }

    /// Wipes the recombined material; every later derivation fails.
    pub fn revoke(&self) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = None;
        }
    }

    pub fn is_authorized(&self) -> bool {
        self.state
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    pub fn crypto_domain(&self) -> Result<[u8; KEY_SIZE], RouterError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let sealed = guard.as_ref().ok_or(RouterError::AuthenticationFailed)?;
        Ok(sealed.crypto_domain)
    }

    pub fn layout_digest(&self) -> Result<[u8; KEY_SIZE], RouterError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let sealed = guard.as_ref().ok_or(RouterError::AuthenticationFailed)?;
        Ok(sealed.layout_digest)
    }
}

impl PageKeyAuthority for SecretPackState {
    fn derive_page_key(
        &self,
        request: &PageKeyRequest<'_>,
    ) -> Result<PageKeyMaterial, RouterError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let sealed = guard.as_ref().ok_or(RouterError::AuthenticationFailed)?;
        let kind = request.kind_id as usize;
        if kind >= sealed.kinds.len() {
            return Err(RouterError::AuthenticationFailed);
        }
        let slot = request.secret_slot as usize;
        let seed = sealed.kinds[kind]
            .get(slot)
            .and_then(|entry| entry.as_ref())
            .ok_or(RouterError::AuthenticationFailed)?;
        let mut info = Vec::with_capacity(
            request.artifact_commitment.len()
                + 4
                + 1
                + 4
                + request.encoded_handle.len()
                + request.locator_token.len()
                + request.page_nonce.len()
                + KEY_SIZE,
        );
        info.extend_from_slice(request.artifact_commitment);
        info.extend_from_slice(&request.secret_slot.to_be_bytes());
        info.push(request.kind_id);
        info.extend_from_slice(&(request.page_index as u32).to_be_bytes());
        info.extend_from_slice(request.encoded_handle);
        info.extend_from_slice(request.locator_token);
        info.extend_from_slice(request.page_nonce);
        info.extend_from_slice(&self.native_identity);
        let mut key = hkdf_sha256(seed, PAGE_KEY_DOMAIN, &info, KEY_SIZE)
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let commitment_key = hkdf_sha256(seed, COMMITMENT_DOMAIN, &[], KEY_SIZE)
            .map_err(|_| RouterError::AuthenticationFailed)?;
        drop(guard);
        let expected = hmac_sha256_bytes(&commitment_key, &[&key]);
        let mut material = [0u8; KEY_SIZE];
        if !constant_time_eq(&expected, request.expected_key_commitment) {
            key.clear();
            return Err(RouterError::AuthenticationFailed);
        }
        material.copy_from_slice(&key[..KEY_SIZE]);
        key.clear();
        Ok(PageKeyMaterial::from_material(&material))
    }
}

/// Sharded sealed-pack layout: `u8 magic || u8 zero || u16 shardCount || per
/// shard: u8 kind || u8 zero || u16 nonceLen(=12) || u32 wrappedLen || nonce
/// || wrapped`.
fn parse_sealed_pack(bytes: &[u8]) -> Result<Vec<(u8, [u8; NONCE_SIZE], Vec<u8>)>, RouterError> {
    const PACK_MAGIC: u8 = 0x6A;
    if bytes.len() < 4 || bytes[0] != PACK_MAGIC || bytes[1] != 0 {
        return Err(RouterError::AuthenticationFailed);
    }
    let count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let mut cursor = 4usize;
    let mut shards = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.len() < cursor + 8 {
            return Err(RouterError::AuthenticationFailed);
        }
        let kind = bytes[cursor];
        if bytes[cursor + 1] != 0 {
            return Err(RouterError::AuthenticationFailed);
        }
        let nonce_len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        let wrapped_len =
            u32::from_be_bytes([bytes[cursor + 4], bytes[cursor + 5], bytes[cursor + 6], bytes[cursor + 7]])
                as usize;
        cursor += 8;
        if nonce_len != NONCE_SIZE {
            return Err(RouterError::AuthenticationFailed);
        }
        let nonce_end = cursor.checked_add(nonce_len).ok_or(RouterError::AuthenticationFailed)?;
        let wrapped_end = nonce_end.checked_add(wrapped_len).ok_or(RouterError::AuthenticationFailed)?;
        if bytes.len() < wrapped_end {
            return Err(RouterError::AuthenticationFailed);
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[cursor..nonce_end]);
        shards.push((kind, nonce, bytes[nonce_end..wrapped_end].to_vec()));
        cursor = wrapped_end;
    }
    if cursor != bytes.len() {
        return Err(RouterError::AuthenticationFailed);
    }
    Ok(shards)
}

fn parse_shard(
    plaintext: &[u8],
    kind: u8,
    kinds: &mut Vec<Vec<Option<[u8; KEY_SIZE]>>>,
    root: &mut Option<([u8; KEY_SIZE], [u8; KEY_SIZE], usize)>,
    expected_identity: &[u8; KEY_SIZE],
) -> Result<(), RouterError> {
    if kind == SHARD_KIND_ROOT {
        if plaintext.len() != KEY_SIZE + 4 + KEY_SIZE + KEY_SIZE {
            return Err(RouterError::AuthenticationFailed);
        }
        if !constant_time_eq(&plaintext[..KEY_SIZE], expected_identity) {
            return Err(RouterError::AuthenticationFailed);
        }
        let total =
            u32::from_be_bytes(plaintext[KEY_SIZE..KEY_SIZE + 4].try_into().map_err(|_| {
                RouterError::AuthenticationFailed
            })?) as usize;
        if total > specialization::SECRET_PACK_SLOT_COUNT {
            return Err(RouterError::AuthenticationFailed);
        }
        let mut crypto_domain = [0u8; KEY_SIZE];
        crypto_domain.copy_from_slice(&plaintext[KEY_SIZE + 4..KEY_SIZE + 4 + KEY_SIZE]);
        let mut layout_digest = [0u8; KEY_SIZE];
        layout_digest.copy_from_slice(&plaintext[KEY_SIZE + 4 + KEY_SIZE..]);
        if crypto_domain == [0u8; KEY_SIZE] || layout_digest == [0u8; KEY_SIZE] {
            return Err(RouterError::AuthenticationFailed);
        }
        if root.replace((crypto_domain, layout_digest, total)).is_some() {
            return Err(RouterError::AuthenticationFailed);
        }
        return Ok(());
    }
    let kind_index = kind as usize;
    if kind_index >= specialization::SECRET_PACK_KIND_COUNT {
        return Err(RouterError::AuthenticationFailed);
    }
    if plaintext.len() < 5 {
        return Err(RouterError::AuthenticationFailed);
    }
    if plaintext[0] != kind {
        return Err(RouterError::AuthenticationFailed);
    }
    let count =
        u32::from_be_bytes(plaintext[1..5].try_into().map_err(|_| RouterError::AuthenticationFailed)?)
            as usize;
    let record = 4 + KEY_SIZE;
    let expected_len = 5usize
        .checked_add(record.checked_mul(count).ok_or(RouterError::AuthenticationFailed)?)
        .ok_or(RouterError::AuthenticationFailed)?;
    if plaintext.len() != expected_len || count > specialization::SECRET_PACK_SLOT_COUNT {
        return Err(RouterError::AuthenticationFailed);
    }
    let mut slots = std::mem::take(&mut kinds[kind_index]);
    if slots.is_empty() {
        slots = vec![None; specialization::SECRET_PACK_SLOT_COUNT];
    }
    let mut cursor = 5usize;
    for _ in 0..count {
        let slot_id = u32::from_be_bytes(
            plaintext[cursor..cursor + 4]
                .try_into()
                .map_err(|_| RouterError::AuthenticationFailed)?,
        ) as usize;
        cursor += 4;
        if slot_id >= slots.len() {
            return Err(RouterError::AuthenticationFailed);
        }
        let mut seed = [0u8; KEY_SIZE];
        seed.copy_from_slice(&plaintext[cursor..cursor + KEY_SIZE]);
        cursor += KEY_SIZE;
        if seed == [0u8; KEY_SIZE] || slots[slot_id].is_some() {
            seed.fill(0);
            return Err(RouterError::AuthenticationFailed);
        }
        slots[slot_id] = Some(seed);
    }
    kinds[kind_index] = slots;
    Ok(())
}

/// v6 sealed VM entry token: `nonce(12) || ct||tag`, AES-256-GCM under
/// `HKDF(cryptoDomain, "javashroud-qp-entry-token-v6")`, AAD = domain.
pub fn unwrap_vm_entry_token(
    crypto_domain: &[u8; KEY_SIZE],
    sealed: &[u8],
) -> Result<i64, RouterError> {
    if sealed.len() < 12 + 16 {
        return Err(RouterError::AuthenticationFailed);
    }
    let key = hkdf_sha256(crypto_domain, ENTRY_TOKEN_DOMAIN, &[], KEY_SIZE)
        .map_err(|_| RouterError::AuthenticationFailed)?;
    let plaintext = aes256_gcm_decrypt(&key, &sealed[..12], ENTRY_TOKEN_DOMAIN, &sealed[12..])
        .map_err(|_| RouterError::AuthenticationFailed)?;
    if plaintext.len() != 8 {
        return Err(RouterError::AuthenticationFailed);
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&plaintext);
    Ok(i64::from_be_bytes(raw))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_sealed_pack_fails_closed() {
        assert!(parse_sealed_pack(&[0x6A, 0, 0]).is_err());
    }

    #[test]
    fn wrong_magic_fails_closed() {
        assert!(parse_sealed_pack(&[0x00, 0, 0, 0]).is_err());
    }

    #[test]
    fn empty_shard_list_parses() {
        let bytes = [0x6A, 0, 0, 0];
        let shards = parse_sealed_pack(&bytes).expect("parse");
        assert!(shards.is_empty());
    }

    #[test]
    fn shard_nonce_must_be_twelve_bytes() {
        let mut bytes = vec![0x6A, 0, 1, 0];
        bytes.push(1); // kind
        bytes.push(0);
        bytes.extend_from_slice(&11u16.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_sealed_pack(&bytes).is_err());
    }
}

#[cfg(test)]
mod blob_tests {
    use super::*;

    #[test]
    fn kotlin_shard_container_layout_parses() {
        // Mirrors NativeSecretPackLiterals.sealForPlatform: 0x6A,0,u16 count,
        // then per shard: kind,0,u16 nonceLen,u32 wrappedLen,nonce,wrapped.
        let mut blob = vec![0x6A, 0];
        blob.extend_from_slice(&2u16.to_be_bytes());
        for (kind, payload) in [(0u8, vec![7u8; 100]), (1u8, vec![9u8; 48])] {
            blob.push(kind);
            blob.push(0);
            blob.extend_from_slice(&12u16.to_be_bytes());
            blob.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            blob.extend_from_slice(&[1u8; 12]);
            blob.extend_from_slice(&payload);
        }
        let shards = parse_sealed_pack(&blob).expect("parse");
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].0, 0);
        assert_eq!(shards[1].0, 1);
        assert_eq!(shards[1].2.len(), 48);
    }
}

#[cfg(test)]
mod entry_token_tests {
    use super::*;
    use qp_crypto::aes256_gcm_encrypt;


    #[test]
    fn vm_entry_token_round_trips_and_rejects_tampering() {
        let crypto_domain = [0x77u8; KEY_SIZE];
        let key = hkdf_sha256(&crypto_domain, ENTRY_TOKEN_DOMAIN, &[], KEY_SIZE).expect("key");
        let nonce = [0x21u8; 12];
        let token: i64 = 0x6f0754c88ca44c64;
        let sealed_ct = aes256_gcm_encrypt(&key, &nonce, ENTRY_TOKEN_DOMAIN, &token.to_be_bytes())
            .expect("seal");
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&sealed_ct);
        assert_eq!(
            unwrap_vm_entry_token(&crypto_domain, &sealed).expect("unwrap"),
            token
        );
        let mut wrong_domain = crypto_domain;
        wrong_domain[0] ^= 1;
        assert!(unwrap_vm_entry_token(&wrong_domain, &sealed).is_err());
        assert!(unwrap_vm_entry_token(&crypto_domain, &sealed[..sealed.len() - 1]).is_err());
        assert!(unwrap_vm_entry_token(&crypto_domain, &[]).is_err());
    }
}
