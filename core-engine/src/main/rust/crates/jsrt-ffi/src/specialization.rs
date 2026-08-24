//! Default nonsecret specialization overwritten in isolated per-artifact builds.

pub const TARGET_TRIPLE: &str = if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
    "x86_64-pc-windows-gnu"
} else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    "x86_64-unknown-linux-gnu.2.17"
} else {
    "unsupported"
};

pub const SPECIALIZATION_DIGEST: [u8; 32] = [0; 32];
pub const PAYLOAD_PROFILE: &str = "aken-r1-rust-ffi-v1";
pub const PROTECTION_LEVEL: &str = "standard";
pub const PACKING_LEVEL: &str = "off";
pub const VM_CRYPTO_DOMAIN: [u8; 32] = [0; 32];
pub const VM_LAYOUT_DIGEST: [u8; 32] = [0; 32];
