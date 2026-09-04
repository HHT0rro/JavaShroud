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
pub const VM_CRYPTO_DOMAIN: [u8; 32] = [0; 32];
pub const VM_LAYOUT_DIGEST: [u8; 32] = [0; 32];
pub const TARGET_TOKEN_COMMITMENT: [u8; 32] = [0; 32];
pub const TARGET_TOKEN_NAME_SEED: [u8; 16] = [0; 16];

/// Build-scoped native identity bound into every structured page-key
/// derivation. Zero in the default (non-generated) specialization.
pub const SECRET_PACK_NATIVE_IDENTITY: [u8; 32] = [0; 32];

/// Number of secret-pack slots emitted by the artifact specialization build.
pub const SECRET_PACK_SLOT_COUNT: usize = 0;

/// Returns the recombined seed for one slot index. The default specialization
/// never carries secret material and always returns `None`.
pub fn qp_secret_pack_seed(_slot: usize) -> Option<[u8; 32]> {
    None
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
