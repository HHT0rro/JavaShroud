//! Default nonsecret specialization overwritten in isolated per-artifact builds.

pub const TARGET_TRIPLE: &str = if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
    "x86_64-pc-windows-gnu"
} else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    "x86_64-unknown-linux-gnu.2.17"
} else {
    "unsupported"
};

pub const SPECIALIZATION_DIGEST: [u8; 32] = [0; 32];
pub const PAYLOAD_PROFILE: &str = "qp-rust-ffi-v1";
pub const PROTECTION_LEVEL: &str = "standard";
pub const PACKING_LEVEL: &str = "off";
/// Live values are recovered from the AEAD wrap after catalog authorization.
pub const VM_CRYPTO_DOMAIN: [u8; 32] = [0; 32];
pub const VM_LAYOUT_DIGEST: [u8; 32] = [0; 32];
pub const TARGET_TOKEN_COMMITMENT: [u8; 32] = [0; 32];
pub const TARGET_TOKEN_NAME_SEED: [u8; 16] = [0; 16];

/// Build-scoped native identity bound into every structured page-key
/// derivation. Zero in the default (non-generated) specialization.
pub const SECRET_PACK_NATIVE_IDENTITY: [u8; 32] = [0; 32];

/// Number of secret-pack slots emitted by the artifact specialization build.
pub const SECRET_PACK_SLOT_COUNT: usize = 0;

/// Number of independently wrapped secret-pack shards: one root shard plus one
/// shard per resource kind (index 0 is unused; kinds are 1-based).
pub const SECRET_PACK_KIND_COUNT: usize = 5;

/// Number of sealed shards carried by the artifact's catalog pack resource.
pub const SECRET_PACK_SHARD_COUNT: usize = 0;

/// Per-shard mask master; shard masks derive as rotate/xor variants of it.
pub const SHARD_MASK_R: [u8; 32] = [0; 32];

/// Commitment-chained shard key halves. The effective shard key is
/// `MASKED[i] ^ R_i ^ image_commitment` where the commitment is only fully
/// formed after the compiled image has been measured and patched, and is read
/// through a volatile load, so no contiguous shard key exists in the file.
#[used]
#[link_section = ".jsmk"]
pub static SHARD_KEYS_MASKED: [u8; 32 * SECRET_PACK_SHARD_COUNT] = [0; 32 * SECRET_PACK_SHARD_COUNT];

fn shard_mask_r(shard: usize) -> [u8; 32] {
    let mut mask = [0u8; 32];
    for (index, byte) in mask.iter_mut().enumerate() {
        *byte = SHARD_MASK_R[(index + 7 * shard + 3) % 32] ^ (shard as u8);
    }
    mask
}

#[repr(C)]
pub struct ImageMeasurementSlot {
    pub magic: [u8; 8],
    pub commitment: [u8; 32],
}

#[used]
#[link_section = ".jsms"]
pub static IMAGE_MEASUREMENT: ImageMeasurementSlot = ImageMeasurementSlot {
    magic: *b"JSIM\x01v6\0",
    commitment: [0; 32],
};

#[inline(never)]
pub fn image_measurement_commitment() -> [u8; 32] {
    unsafe { core::ptr::read_volatile(&IMAGE_MEASUREMENT.commitment) }
}

/// Reconstructs the effective static half of one shard's wrap key. Shard keys
/// are finished at runtime by mixing the image commitment through a volatile
/// read, so they can never be constant-folded into a contiguous static window.
pub fn qp_sp_reconstruct_shard_key(shard: usize) -> [u8; 32] {
    if shard >= SECRET_PACK_SHARD_COUNT {
        return [0; 32];
    }
    let commitment = image_measurement_commitment();
    let mask = shard_mask_r(shard);
    let base = shard * 32;
    let mut key = [0u8; 32];
    for index in 0..32 {
        key[index] = SHARD_KEYS_MASKED[base + index] ^ mask[index] ^ commitment[index % 32];
    }
    key
}

/// Random per-build half of the VM dialect mask; the other half is the
/// counter-mode SHA-256 expansion of the volatile image commitment, so the
/// adjacent static bytes never reconstruct the corpus offline.
pub const VM_DIALECT_SEMANTIC_MASK: [u8; 0] = [];
/// Masked serialization of the VM semantic opcode corpus (big-endian pairs).
pub const VM_DIALECT_SEMANTIC_MASKED: [u8; 0] = [];

/// Reconstructs the per-build VM semantic opcode corpus. The default
/// (non-generated) specialization carries no corpus and production builds
/// fail closed when it is missing.
pub fn vm_dialect_semantic_opcodes() -> Vec<u16> {
    Vec::new()
}
