//! Per-artifact native secret pack.
//!
//! The generated specialization embeds every page-key seed as randomized XOR
//! shard groups. This module recombines those shards once, after the bridge
//! has authenticated the catalog and session, and derives page keys from
//! structured binary inputs only. There is no descriptor-carried evaluator,
//! no public string concatenation, and no key material outside the shards and
//! the short-lived derived keys. Defense violations revoke the recombined
//! state and every later page open fails closed.

use crate::specialization;
use qp_crypto::{constant_time_eq, hmac_sha256_bytes, hkdf_sha256};
use qp_runtime::{PageKeyAuthority, PageKeyMaterial, PageKeyRequest, RouterError};
use std::sync::Mutex;

const PAGE_KEY_DOMAIN: &[u8] = b"javashroud-qp-page-key-v4";
const COMMITMENT_DOMAIN: &[u8] = b"javashroud-qp-secret-commitment-v4";
const KEY_SIZE: usize = 32;

struct Recombined {
    seeds: Vec<[u8; KEY_SIZE]>,
}

impl Drop for Recombined {
    fn drop(&mut self) {
        for seed in &mut self.seeds {
            seed.fill(0);
        }
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

    /// Recombines the shard groups exactly once. `authorized == false`, a
    /// missing pack, a truncated pack, or an all-zero seed keeps the pack
    /// sealed so every later page open fails closed.
    pub fn authorize(&self, authorized: bool) -> Result<(), RouterError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        if guard.is_some() {
            return Ok(());
        }
        if !authorized || specialization::SECRET_PACK_SLOT_COUNT == 0 {
            return Err(RouterError::AuthenticationFailed);
        }
        let mut seeds = Vec::with_capacity(specialization::SECRET_PACK_SLOT_COUNT);
        for slot in 0..specialization::SECRET_PACK_SLOT_COUNT {
            let seed = specialization::qp_secret_pack_seed(slot)
                .ok_or(RouterError::AuthenticationFailed)?;
            if seed == [0u8; KEY_SIZE] {
                return Err(RouterError::AuthenticationFailed);
            }
            seeds.push(seed);
        }
        *guard = Some(Recombined { seeds });
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
        // Structured binary derivation inputs. The byte order must stay
        // identical to the build-side secret pack: commitment, slot, kind,
        // page index, handle, locator, page nonce, native identity.
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
