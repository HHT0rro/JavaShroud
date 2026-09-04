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

/// Reconstructs the static half of one shard's wrap key from per-build MBA
/// immediates. Shard keys are finished at runtime by mixing the image
/// commitment, so this static half alone decrypts nothing.
pub fn qp_sp_reconstruct_shard_key(_shard: usize) -> [u8; 32] {
    [0; 32]
}

/// XOR mask over the serialized per-build VM semantic opcode corpus.
pub const VM_DIALECT_SEMANTIC_MASK: [u8; 0] = [];
/// Masked serialization of the VM semantic opcode corpus (big-endian pairs).
pub const VM_DIALECT_SEMANTIC_MASKED: [u8; 0] = [];

/// Reconstructs the per-build VM semantic opcode corpus. The default
/// (non-generated) specialization carries no corpus and production builds
/// fail closed when it is missing.
pub fn vm_dialect_semantic_opcodes() -> Vec<u16> {
    Vec::new()
}
