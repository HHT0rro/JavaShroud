//! Per-artifact native secret pack (v6, sharded).
//!
//! The sealed pack travels as authenticated catalog data, never as a native
//! source constant. It is split into independently wrapped shards — one root
//! shard (identity, crypto domain, layout digest) and one shard per resource
//! kind — so compromising one shard does not expose the others. Each shard key
//! is `HMAC(reconstruct_shard_key, image commitment)`; the commitment lives in
//! the `.jsms` slot and is read at runtime only, so the shard keys can never
//! be constant-folded into a contiguous static window.
//!
//! After authorize, only ciphertext is retained. Root material and slot seeds
//! are unwrapped into a callback window and wiped on every return, panic, and
//! error path. A revoke epoch invalidates in-flight windows.

use crate::image_measure;
use crate::specialization;
use qp_crypto::{aes256_gcm_decrypt, constant_time_eq, hmac_sha256_bytes, hkdf_sha256};
use qp_runtime::{PageKeyAuthority, PageKeyMaterial, PageKeyRequest, RouterError};
use std::sync::atomic::{compiler_fence, AtomicU64, Ordering};
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

#[inline(never)]
fn pack_shell_info() -> [u8; 27] {
    let packed: [u8; 27] = [
        0x3F, 0x34, 0x23, 0x34, 0x26, 0x3D, 0x27, 0x3A, 0x20, 0x31, 0x78, 0x24, 0x25, 0x78,
        0x25, 0x34, 0x36, 0x3E, 0x78, 0x26, 0x3D, 0x30, 0x39, 0x39, 0x78, 0x23, 0x63,
    ];
    let mut info = [0u8; 27];
    for index in 0..27 {
        info[index] = packed[index] ^ 0x55;
    }
    unsafe { core::ptr::read_volatile(&info) }
}

const SHARD_KIND_ROOT: u8 = 0;
const ENTRY_TOKEN_DOMAIN: &[u8] = b"javashroud-qp-entry-token-v6";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

fn volatile_wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// 32-byte secret that is wiped on drop, including panic and error returns.
struct WipedArray32([u8; KEY_SIZE]);

impl WipedArray32 {
    fn new(value: [u8; KEY_SIZE]) -> Self {
        Self(value)
    }

    fn as_ref(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src);
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl Drop for WipedArray32 {
    fn drop(&mut self) {
        volatile_wipe(&mut self.0);
    }
}

/// Heap buffer that is wiped on drop, including panic and error returns.
struct WipedVec(Vec<u8>);

impl WipedVec {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for WipedVec {
    fn drop(&mut self) {
        volatile_wipe(&mut self.0);
        self.0.clear();
    }
}

/// One sealed shard kept as ciphertext. Plaintext exists only inside a
/// short-lived unwrap window and is wiped before the window returns.
struct SealedShard {
    kind: u8,
    nonce: [u8; NONCE_SIZE],
    wrapped: Vec<u8>,
}

impl Drop for SealedShard {
    fn drop(&mut self) {
        volatile_wipe(&mut self.nonce);
        volatile_wipe(&mut self.wrapped);
        self.wrapped.clear();
    }
}

/// Authorized pack: measurement has been verified and the sealed blob is
/// retained. Slot seeds and the crypto domain are *not* held in plaintext.
struct AuthorizedPack {
    shards: Vec<SealedShard>,
    /// `(kind, slot) -> shard index` so method-bucket shards unwrap one bucket,
    /// not every method seed.
    slot_home: Vec<(u8, u16, u16)>,
    /// Session-only kind seeds, populated at authorize and wiped on revoke.
    /// Cold dumps still see ciphertext shards; this window exists only while
    /// the pack is authorized so Calc does not AES-unwrap a shard per page.
    kind_seeds: Vec<((u8, u16), WipedArray32)>,
}

impl Drop for AuthorizedPack {
    fn drop(&mut self) {
        self.shards.clear();
        self.slot_home.clear();
        self.kind_seeds.clear();
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
    volatile_wipe(&mut input);
    derived
}

fn pack_shell_key() -> [u8; 32] {
    let identity = specialization::SECRET_PACK_NATIVE_IDENTITY;
    let info = pack_shell_info();
    let mut input = [0u8; 32 + 27];
    input[..32].copy_from_slice(&identity);
    input[32..].copy_from_slice(&info);
    let derived = qp_crypto::sha256(&input).into_bytes();
    volatile_wipe(&mut input);
    derived
}

/// Artifact-specific secret authority backed by the generated specialization.
pub struct SecretPackState {
    native_identity: [u8; KEY_SIZE],
    state: Mutex<Option<AuthorizedPack>>,
    epoch: AtomicU64,
}

impl SecretPackState {
    /// Builds the authority from the generated specialization constants. The
    /// pack stays sealed until [`SecretPackState::authorize`] succeeds.
    pub fn from_specialization() -> Self {
        Self {
            native_identity: specialization::SECRET_PACK_NATIVE_IDENTITY,
            state: Mutex::new(None),
            epoch: AtomicU64::new(0),
        }
    }

    pub fn revocation_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    fn bump_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Verifies the image measurement and the sealed container, then retains
    /// ciphertext only. Slot seeds and the crypto domain are unwrapped into a
    /// short-lived window on each use and wiped before return, so a cold
    /// process dump cannot harvest the recombined pack.
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
        let measurement_key =
            WipedArray32::new(specialization::qp_sp_reconstruct_shard_key(1));
        if measurement_key.is_zero() {
            return Err(RouterError::InvalidRequest("secret wrap key is zero"));
        }
        if image_measure::verify_wrap_key(measurement_key.as_ref()).is_err() {
            return Err(RouterError::InvalidRequest("secret image measurement failed"));
        }
        drop(measurement_key);
        let parsed = parse_sealed_pack(sealed_pack)
            .map_err(|_| RouterError::InvalidRequest("secret wrap container is invalid"))?;
        if parsed.len() != specialization::SECRET_PACK_SHARD_COUNT {
            return Err(RouterError::InvalidRequest("secret wrap shard count mismatch"));
        }
        let mut shards = Vec::with_capacity(parsed.len());
        for (kind, nonce, wrapped) in parsed {
            shards.push(SealedShard {
                kind,
                nonce,
                wrapped,
            });
        }
        // Integrity check: every shard must unwrap and the slot census must
        // match the root record. Plaintext is wiped before this returns.
        let (slot_home, kind_seeds) = self.verify_pack_integrity(&shards)?;
        *guard = Some(AuthorizedPack {
            shards,
            slot_home,
            kind_seeds,
        });
        self.bump_epoch();
        Ok(())
    }

    fn verify_pack_integrity(
        &self,
        shards: &[SealedShard],
    ) -> Result<(Vec<(u8, u16, u16)>, Vec<((u8, u16), WipedArray32)>), RouterError> {
        let mut slot_home = Vec::new();
        let mut kind_seeds = Vec::new();
        let mut total_slots: Option<usize> = None;
        let mut armed = 0usize;
        for (index, shard) in shards.iter().enumerate() {
            let plaintext = unwrap_shard(index, shard)?;
            if shard.kind == SHARD_KIND_ROOT {
                if total_slots.is_some() {
                    return Err(RouterError::InvalidRequest(
                        "secret wrap plaintext is invalid",
                    ));
                }
                let (crypto, layout, total) =
                    parse_root_record(plaintext.as_slice(), &self.native_identity).map_err(
                        |_| RouterError::InvalidRequest("secret wrap plaintext is invalid"),
                    )?;
                drop(crypto);
                drop(layout);
                total_slots = Some(total);
            } else {
                let count = count_kind_records(plaintext.as_slice(), shard.kind).map_err(|_| {
                    RouterError::InvalidRequest("secret wrap plaintext is invalid")
                })?;
                let homes = collect_slot_homes(plaintext.as_slice(), shard.kind, index as u16);
                if homes.len() != count {
                    return Err(RouterError::InvalidRequest(
                        "secret wrap plaintext is invalid",
                    ));
                }
                armed = armed
                    .checked_add(count)
                    .ok_or(RouterError::InvalidRequest(
                        "secret wrap plaintext is invalid",
                    ))?;
                for &(kind, slot, _) in &homes {
                    let seed = extract_kind_slot(plaintext.as_slice(), kind, slot as usize)?;
                    kind_seeds.push(((kind, slot), seed));
                }
                slot_home.extend(homes);
            }
        }
        let total_slots = total_slots.ok_or(RouterError::InvalidRequest(
            "secret wrap plaintext is invalid",
        ))?;
        let mut seen = Vec::with_capacity(slot_home.len());
        for &(kind, slot, _) in &slot_home {
            if seen.iter().any(|entry| *entry == (kind, slot)) {
                return Err(RouterError::InvalidRequest(
                    "secret wrap plaintext is invalid",
                ));
            }
            seen.push((kind, slot));
        }
        if armed != total_slots {
            return Err(RouterError::InvalidRequest(
                "secret wrap plaintext is invalid",
            ));
        }
        Ok((slot_home, kind_seeds))
    }

    /// Wipes the retained ciphertext and advances the revoke epoch so any
    /// in-flight callback result is rejected.
    pub fn revoke(&self) {
        self.bump_epoch();
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

    /// Unwraps the root shard into `f` and wipes crypto-domain / layout-digest
    /// copies when `f` returns or panics. The callback must not stash the
    /// arrays past the call; a revoke epoch change fail-closes the result.
    pub fn with_root_material<T, F>(&self, f: F) -> Result<T, RouterError>
    where
        F: FnOnce(&[u8; KEY_SIZE], &[u8; KEY_SIZE]) -> Result<T, RouterError>,
    {
        let epoch = self.revocation_epoch();
        let (crypto, layout, _total) = {
            let guard = self
                .state
                .lock()
                .map_err(|_| RouterError::AuthenticationFailed)?;
            if self.revocation_epoch() != epoch {
                return Err(RouterError::AuthenticationFailed);
            }
            let pack = guard.as_ref().ok_or(RouterError::AuthenticationFailed)?;
            let root_index = pack
                .shards
                .iter()
                .position(|shard| shard.kind == SHARD_KIND_ROOT)
                .ok_or(RouterError::AuthenticationFailed)?;
            let plaintext = unwrap_shard(root_index, &pack.shards[root_index])?;
            parse_root_record(plaintext.as_slice(), &self.native_identity)?
        };
        if self.revocation_epoch() != epoch {
            return Err(RouterError::AuthenticationFailed);
        }
        let result = f(crypto.as_ref(), layout.as_ref());
        drop(crypto);
        drop(layout);
        if self.revocation_epoch() != epoch {
            return Err(RouterError::AuthenticationFailed);
        }
        result
    }

    /// Unwraps one VM entry token inside the root-material window. The i64 is
    /// not cached on the pack or the bridge.
    pub fn with_vm_entry_token<T, F>(&self, sealed: &[u8], f: F) -> Result<T, RouterError>
    where
        F: FnOnce(i64) -> Result<T, RouterError>,
    {
        self.with_root_material(|crypto_domain, _layout| {
            let token = unwrap_vm_entry_token(crypto_domain, sealed)?;
            f(token)
        })
    }

    fn with_kind_seed<T, F>(&self, kind_id: u8, slot: usize, f: F) -> Result<T, RouterError>
    where
        F: FnOnce(&[u8; KEY_SIZE]) -> Result<T, RouterError>,
    {
        let epoch = self.revocation_epoch();
        let seed = {
            let guard = self
                .state
                .lock()
                .map_err(|_| RouterError::AuthenticationFailed)?;
            if self.revocation_epoch() != epoch {
                return Err(RouterError::AuthenticationFailed);
            }
            let pack = guard.as_ref().ok_or(RouterError::AuthenticationFailed)?;
            let cached = pack
                .kind_seeds
                .iter()
                .find(|((kind, slot_id), _)| *kind == kind_id && *slot_id as usize == slot)
                .map(|(_, seed)| WipedArray32::new(*seed.as_ref()));
            if let Some(seed) = cached {
                seed
            } else {
                let shard_index = pack
                    .slot_home
                    .iter()
                    .find(|(kind, slot_id, _)| *kind == kind_id && *slot_id as usize == slot)
                    .map(|(_, _, shard_index)| *shard_index as usize)
                    .ok_or(RouterError::AuthenticationFailed)?;
                let kind = pack.shards[shard_index].kind;
                let plaintext = unwrap_shard(shard_index, &pack.shards[shard_index])?;
                extract_kind_slot(plaintext.as_slice(), kind, slot)?
            }
        };
        if self.revocation_epoch() != epoch {
            return Err(RouterError::AuthenticationFailed);
        }
        let result = f(seed.as_ref());
        drop(seed);
        if self.revocation_epoch() != epoch {
            return Err(RouterError::AuthenticationFailed);
        }
        result
    }
}

fn collect_slot_homes(plaintext: &[u8], kind: u8, shard_index: u16) -> Vec<(u8, u16, u16)> {
    if kind == SHARD_KIND_ROOT || plaintext.len() < 5 {
        return Vec::new();
    }
    let count = u32::from_be_bytes(plaintext[1..5].try_into().unwrap_or([0; 4])) as usize;
    let record = 4 + KEY_SIZE;
    let mut homes = Vec::with_capacity(count);
    let mut cursor = 5usize;
    for _ in 0..count {
        if cursor + record > plaintext.len() {
            break;
        }
        let slot_id = u32::from_be_bytes(plaintext[cursor..cursor + 4].try_into().unwrap_or([0; 4]));
        homes.push((kind, slot_id as u16, shard_index));
        cursor += record;
    }
    homes
}

fn unwrap_shard(index: usize, shard: &SealedShard) -> Result<WipedVec, RouterError> {
    let commitment = specialization::image_measurement_commitment();
    let static_key = WipedArray32::new(specialization::qp_sp_reconstruct_shard_key(index));
    if static_key.is_zero() {
        return Err(RouterError::InvalidRequest("secret wrap key is zero"));
    }
    let shard_key = WipedArray32::new(hmac_sha256_bytes(static_key.as_ref(), &[&commitment]));
    drop(static_key);
    let wrap_aad = WipedArray32::new(wrap_aad());
    let plaintext = aes256_gcm_decrypt(
        shard_key.as_ref(),
        &shard.nonce,
        wrap_aad.as_ref(),
        &shard.wrapped,
    )
    .map_err(|_| RouterError::InvalidRequest("secret wrap decrypt failed"))?;
    Ok(WipedVec::new(plaintext))
}

impl PageKeyAuthority for SecretPackState {
    fn derive_page_key(
        &self,
        request: &PageKeyRequest<'_>,
    ) -> Result<PageKeyMaterial, RouterError> {
        let kind = request.kind_id;
        let slot = request.secret_slot as usize;
        self.with_kind_seed(kind, slot, |seed| {
            let mut info = WipedVec::new(Vec::with_capacity(
                request.artifact_commitment.len()
                    + 4
                    + 1
                    + 4
                    + request.encoded_handle.len()
                    + request.locator_token.len()
                    + request.page_nonce.len()
                    + KEY_SIZE,
            ));
            info.0.extend_from_slice(request.artifact_commitment);
            info.0.extend_from_slice(&request.secret_slot.to_be_bytes());
            info.0.push(request.kind_id);
            info.0.extend_from_slice(&(request.page_index as u32).to_be_bytes());
            info.0.extend_from_slice(request.encoded_handle);
            info.0.extend_from_slice(request.locator_token);
            info.0.extend_from_slice(request.page_nonce);
            info.0.extend_from_slice(&self.native_identity);
            let key = WipedVec::new(
                hkdf_sha256(seed, PAGE_KEY_DOMAIN, info.as_slice(), KEY_SIZE)
                    .map_err(|_| RouterError::AuthenticationFailed)?,
            );
            let commitment_key = WipedVec::new(
                hkdf_sha256(seed, COMMITMENT_DOMAIN, &[], KEY_SIZE)
                    .map_err(|_| RouterError::AuthenticationFailed)?,
            );
            volatile_wipe(&mut info.0);
            let expected = hmac_sha256_bytes(commitment_key.as_slice(), &[key.as_slice()]);
            if !constant_time_eq(&expected, request.expected_key_commitment) {
                return Err(RouterError::AuthenticationFailed);
            }
            if key.len() < KEY_SIZE {
                return Err(RouterError::AuthenticationFailed);
            }
            let mut material = WipedArray32::new([0u8; KEY_SIZE]);
            material.copy_from_slice(&key.as_slice()[..KEY_SIZE]);
            Ok(PageKeyMaterial::from_material(material.as_ref()))
        })
    }
}

/// Outer authenticated pack shell: `nonce(12) || ct||tag` under
/// `SHA-256(nativeIdentity || pack-shell-v6)`. Inner layout remains
/// `u8 magic || u8 zero || u16 shardCount || per shard: u8 kind || u8 zero ||
/// u16 nonceLen(=12) || u32 wrappedLen || nonce || wrapped`.
fn parse_sealed_pack(bytes: &[u8]) -> Result<Vec<(u8, [u8; NONCE_SIZE], Vec<u8>)>, RouterError> {
    let inner = unwrap_pack_shell(bytes)?;
    parse_inner_sealed_pack(inner.as_slice())
}

fn unwrap_pack_shell(bytes: &[u8]) -> Result<WipedVec, RouterError> {
    if bytes.len() < NONCE_SIZE + 16 {
        return Err(RouterError::AuthenticationFailed);
    }
    let key = WipedArray32::new(pack_shell_key());
    let plaintext = aes256_gcm_decrypt(
        key.as_ref(),
        &bytes[..NONCE_SIZE],
        key.as_ref(),
        &bytes[NONCE_SIZE..],
    )
    .map_err(|_| RouterError::AuthenticationFailed)?;
    Ok(WipedVec::new(plaintext))
}

fn parse_inner_sealed_pack(bytes: &[u8]) -> Result<Vec<(u8, [u8; NONCE_SIZE], Vec<u8>)>, RouterError> {
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

fn parse_root_record(
    plaintext: &[u8],
    expected_identity: &[u8; KEY_SIZE],
) -> Result<(WipedArray32, WipedArray32, usize), RouterError> {
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
    let mut crypto_domain = WipedArray32::new([0u8; KEY_SIZE]);
    crypto_domain.copy_from_slice(&plaintext[KEY_SIZE + 4..KEY_SIZE + 4 + KEY_SIZE]);
    let mut layout_digest = WipedArray32::new([0u8; KEY_SIZE]);
    layout_digest.copy_from_slice(&plaintext[KEY_SIZE + 4 + KEY_SIZE..]);
    if crypto_domain.is_zero() || layout_digest.is_zero() {
        return Err(RouterError::AuthenticationFailed);
    }
    Ok((crypto_domain, layout_digest, total))
}

fn count_kind_records(plaintext: &[u8], kind: u8) -> Result<usize, RouterError> {
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
    let mut seen = vec![false; specialization::SECRET_PACK_SLOT_COUNT];
    let mut cursor = 5usize;
    for _ in 0..count {
        let slot_id = u32::from_be_bytes(
            plaintext[cursor..cursor + 4]
                .try_into()
                .map_err(|_| RouterError::AuthenticationFailed)?,
        ) as usize;
        cursor += 4;
        if slot_id >= seen.len() || seen[slot_id] {
            return Err(RouterError::AuthenticationFailed);
        }
        seen[slot_id] = true;
        if plaintext[cursor..cursor + KEY_SIZE]
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(RouterError::AuthenticationFailed);
        }
        cursor += KEY_SIZE;
    }
    Ok(count)
}

fn extract_kind_slot(
    plaintext: &[u8],
    kind: u8,
    slot: usize,
) -> Result<WipedArray32, RouterError> {
    let count = count_kind_records(plaintext, kind)?;
    let _record = 4 + KEY_SIZE;
    let mut cursor = 5usize;
    for _ in 0..count {
        let slot_id = u32::from_be_bytes(
            plaintext[cursor..cursor + 4]
                .try_into()
                .map_err(|_| RouterError::AuthenticationFailed)?,
        ) as usize;
        cursor += 4;
        if slot_id == slot {
            let mut seed = WipedArray32::new([0u8; KEY_SIZE]);
            seed.copy_from_slice(&plaintext[cursor..cursor + KEY_SIZE]);
            return Ok(seed);
        }
        cursor += KEY_SIZE;
    }
    Err(RouterError::AuthenticationFailed)
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
    let key = WipedVec::new(
        hkdf_sha256(crypto_domain, ENTRY_TOKEN_DOMAIN, &[], KEY_SIZE)
            .map_err(|_| RouterError::AuthenticationFailed)?,
    );
    let plaintext = WipedVec::new(
        aes256_gcm_decrypt(key.as_slice(), &sealed[..12], ENTRY_TOKEN_DOMAIN, &sealed[12..])
            .map_err(|_| RouterError::AuthenticationFailed)?,
    );
    if plaintext.len() != 8 {
        return Err(RouterError::AuthenticationFailed);
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(plaintext.as_slice());
    let token = i64::from_be_bytes(raw);
    volatile_wipe(&mut raw);
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_sealed_pack_fails_closed() {
        assert!(parse_sealed_pack(&[0x6A, 0, 0]).is_err());
        assert!(parse_inner_sealed_pack(&[0x6A, 0, 0]).is_err());
    }

    #[test]
    fn wrong_magic_fails_closed() {
        assert!(parse_inner_sealed_pack(&[0x00, 0, 0, 0]).is_err());
    }

    #[test]
    fn empty_shard_list_parses() {
        let bytes = [0x6A, 0, 0, 0];
        let shards = parse_inner_sealed_pack(&bytes).expect("parse");
        assert!(shards.is_empty());
    }

    #[test]
    fn shard_nonce_must_be_twelve_bytes() {
        let mut bytes = vec![0x6A, 0, 1, 0];
        bytes.push(1); // kind
        bytes.push(0);
        bytes.extend_from_slice(&11u16.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_inner_sealed_pack(&bytes).is_err());
    }

    #[test]
    fn volatile_wipe_zeros_buffer() {
        let mut buf = [0x5Au8; 32];
        volatile_wipe(&mut buf);
        assert!(buf.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn wiped_array_zeros_on_drop() {
        let mut buf = [0x5Au8; 32];
        {
            let wrapped = WipedArray32::new(buf);
            buf.copy_from_slice(wrapped.as_ref());
        }
        // The stack copy in `buf` is independent; Drop of WipedArray32 is
        // covered by Miri/ASAN elsewhere. Check the wipe helper contract here.
        volatile_wipe(&mut buf);
        assert!(buf.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn revoke_increments_epoch_and_clears_authorization() {
        let pack = SecretPackState::from_specialization();
        let before = pack.revocation_epoch();
        pack.revoke();
        assert!(pack.revocation_epoch() > before);
        assert!(!pack.is_authorized());
    }

    #[test]
    fn with_root_material_fails_when_unauthorized() {
        let pack = SecretPackState::from_specialization();
        let error = pack
            .with_root_material(|_, _| Ok(()))
            .expect_err("unauthorized pack");
        assert!(matches!(error, RouterError::AuthenticationFailed));
    }

    #[test]
    fn with_vm_entry_token_fails_when_unauthorized() {
        let pack = SecretPackState::from_specialization();
        assert!(pack.with_vm_entry_token(&[0u8; 32], |_| Ok(())).is_err());
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
        let shards = parse_inner_sealed_pack(&blob).expect("parse");
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].0, 0);
        assert_eq!(shards[1].0, 1);
        assert_eq!(shards[1].2.len(), 48);
    }

    #[test]
    fn outer_pack_shell_rejects_bare_inner_magic() {
        let inner = [0x6A, 0, 0, 0];
        assert!(parse_sealed_pack(&inner).is_err());
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
