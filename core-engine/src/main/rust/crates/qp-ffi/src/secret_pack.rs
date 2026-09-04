//! Per-artifact native secret pack.
//!
//! Slot seeds, VM crypto domain, and layout digest are recovered from an
//! AEAD wrap after catalog and session authentication. The wrap key is
//! reconstructed from per-build MBA immediates and bound to the on-disk
//! image measurement. Defense violations revoke the recombined state.

use crate::image_measure;
use crate::specialization;
use qp_crypto::{aes256_gcm_decrypt, constant_time_eq, hmac_sha256_bytes, hkdf_sha256};
use qp_runtime::{PageKeyAuthority, PageKeyMaterial, PageKeyRequest, RouterError};
use std::sync::Mutex;

const PAGE_KEY_DOMAIN: &[u8] = b"javashroud-qp-page-key-v5";
const COMMITMENT_DOMAIN: &[u8] = b"javashroud-qp-secret-commitment-v5";
const WRAP_AAD: &[u8] = b"javashroud-qp-secret-wrap-v5";
const KEY_SIZE: usize = 32;

struct Recombined {
    seeds: Vec<[u8; KEY_SIZE]>,
    crypto_domain: [u8; KEY_SIZE],
    layout_digest: [u8; KEY_SIZE],
}

impl Drop for Recombined {
    fn drop(&mut self) {
        for seed in &mut self.seeds {
            seed.fill(0);
        }
        self.crypto_domain.fill(0);
        self.layout_digest.fill(0);
    }
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

    /// Unwraps the AEAD pack exactly once. Measurement mismatch, an empty
    /// wrap, or a truncated payload keeps the pack sealed.
    pub fn authorize(&self, authorized: bool) -> Result<(), RouterError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        if guard.is_some() {
            return Ok(());
        }
        if !authorized || specialization::SECRET_PACK_WRAPPED.is_empty() {
            return Err(RouterError::InvalidRequest("secret wrap is empty"));
        }
        let mut wrap_key = specialization::qp_sp_reconstruct_wrap_key();
        if wrap_key == [0u8; KEY_SIZE] {
            return Err(RouterError::InvalidRequest("secret wrap key is zero"));
        }
        let measured = image_measure::verify_wrap_key(&wrap_key);
        if measured.is_err() {
            wrap_key.fill(0);
            return Err(RouterError::InvalidRequest("secret image measurement failed"));
        }
        let plaintext = match aes256_gcm_decrypt(
            &wrap_key,
            &specialization::SECRET_PACK_NONCE,
            WRAP_AAD,
            &specialization::SECRET_PACK_WRAPPED,
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                wrap_key.fill(0);
                return Err(RouterError::InvalidRequest("secret wrap decrypt failed"));
            }
        };
        wrap_key.fill(0);
        let parsed = parse_plaintext(&plaintext, &self.native_identity)
            .map_err(|_| RouterError::InvalidRequest("secret wrap plaintext is invalid"));
        let mut owned = plaintext;
        owned.fill(0);
        let recombined = parsed?;
        *guard = Some(recombined);
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
        let slot = request.secret_slot as usize;
        if slot >= sealed.seeds.len() {
            return Err(RouterError::AuthenticationFailed);
        }
        let seed = &sealed.seeds[slot];
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

fn parse_plaintext(
    plaintext: &[u8],
    expected_identity: &[u8; KEY_SIZE],
) -> Result<Recombined, RouterError> {
    let minimum = KEY_SIZE + 4 + KEY_SIZE + KEY_SIZE;
    if plaintext.len() < minimum {
        return Err(RouterError::AuthenticationFailed);
    }
    let identity = plaintext
        .get(..KEY_SIZE)
        .ok_or(RouterError::AuthenticationFailed)?;
    if !constant_time_eq(identity, expected_identity) {
        return Err(RouterError::AuthenticationFailed);
    }
    let count_bytes: [u8; 4] = plaintext
        .get(KEY_SIZE..KEY_SIZE + 4)
        .ok_or(RouterError::AuthenticationFailed)?
        .try_into()
        .map_err(|_| RouterError::AuthenticationFailed)?;
    let slot_count = u32::from_be_bytes(count_bytes) as usize;
    if slot_count != specialization::SECRET_PACK_SLOT_COUNT {
        return Err(RouterError::AuthenticationFailed);
    }
    let record_bytes = slot_count
        .checked_mul(4 + KEY_SIZE)
        .ok_or(RouterError::AuthenticationFailed)?;
    let records_end = KEY_SIZE
        .checked_add(4)
        .and_then(|start| start.checked_add(record_bytes))
        .ok_or(RouterError::AuthenticationFailed)?;
    let expected_len = records_end
        .checked_add(KEY_SIZE)
        .and_then(|value| value.checked_add(KEY_SIZE))
        .ok_or(RouterError::AuthenticationFailed)?;
    if plaintext.len() != expected_len {
        return Err(RouterError::AuthenticationFailed);
    }
    let mut seeds = vec![[0u8; KEY_SIZE]; slot_count];
    let mut cursor = KEY_SIZE + 4;
    for slot in 0..slot_count {
        let slot_id_bytes: [u8; 4] = plaintext[cursor..cursor + 4]
            .try_into()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let slot_id = u32::from_be_bytes(slot_id_bytes) as usize;
        cursor += 4;
        if slot_id >= slot_count {
            return Err(RouterError::AuthenticationFailed);
        }
        let mut seed = [0u8; KEY_SIZE];
        seed.copy_from_slice(&plaintext[cursor..cursor + KEY_SIZE]);
        cursor += KEY_SIZE;
        if seed == [0u8; KEY_SIZE] || seeds[slot_id] != [0u8; KEY_SIZE] {
            seed.fill(0);
            return Err(RouterError::AuthenticationFailed);
        }
        seeds[slot_id] = seed;
        let _ = slot;
    }
    let mut crypto_domain = [0u8; KEY_SIZE];
    crypto_domain.copy_from_slice(&plaintext[records_end..records_end + KEY_SIZE]);
    let mut layout_digest = [0u8; KEY_SIZE];
    layout_digest.copy_from_slice(&plaintext[records_end + KEY_SIZE..]);
    if crypto_domain == [0u8; KEY_SIZE] || layout_digest == [0u8; KEY_SIZE] {
        return Err(RouterError::AuthenticationFailed);
    }
    Ok(Recombined {
        seeds,
        crypto_domain,
        layout_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_plaintext_fails_closed() {
        let identity = [0x11u8; KEY_SIZE];
        assert!(parse_plaintext(&[0x11u8; 16], &identity).is_err());
    }

    #[test]
    fn identity_mismatch_fails_closed() {
        let identity = [0x11u8; KEY_SIZE];
        let mut plaintext = vec![0u8; KEY_SIZE + 4 + KEY_SIZE + KEY_SIZE];
        plaintext[..KEY_SIZE].fill(0x22);
        assert!(parse_plaintext(&plaintext, &identity).is_err());
    }
}
