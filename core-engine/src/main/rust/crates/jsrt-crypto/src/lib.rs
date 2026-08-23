#![forbid(unsafe_code)]

mod types;
use std::fmt;
use std::sync::OnceLock;
pub use types::{
    Binding, BindingError, Digest, DIGEST_SIZE, MAX_BINDING_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
};

const BLOCK_SIZE: usize = 64;
const AES_BLOCK_SIZE: usize = 16;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = AES_BLOCK_SIZE;
const MAX_GCM_BLOCKS: usize = 0xffff_fffe;
pub const RUNTIME_BINDING_DOMAIN: &[u8] = b"JavaShroud/AKEN-R1/RuntimeBindingDigest/v1";
pub const AUTHENTICATION_DOMAIN: &[u8] = b"JavaShroud/AKEN-R1/AuthenticatedFrame/v1";

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffered: usize,
    bit_len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; BLOCK_SIZE],
            buffered: 0,
            bit_len: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.bit_len = self
            .bit_len
            .wrapping_add((bytes.len() as u64).wrapping_mul(8));
        let mut input = bytes;
        while !input.is_empty() {
            let take = (BLOCK_SIZE - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == BLOCK_SIZE {
                transform(&mut self.state, &self.buffer);
                self.buffered = 0;
            }
        }
    }

    pub fn finalize(mut self) -> Digest {
        let original_bit_len = self.bit_len;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            transform(&mut self.state, &self.buffer);
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&original_bit_len.to_be_bytes());
        transform(&mut self.state, &self.buffer);

        let mut output = [0; DIGEST_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        Digest::from_bytes(output)
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        self.state.fill(0);
        self.buffer.fill(0);
        self.buffered = 0;
        self.bit_len = 0;
    }
}

pub fn sha256(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeBindingDigest(Digest);

impl RuntimeBindingDigest {
    pub fn compute(binding: &Binding) -> Self {
        Self(
            compute_framed(RUNTIME_BINDING_DOMAIN, &[binding.as_bytes()]).expect("bounded binding"),
        )
    }

    pub fn compute_bytes(binding: &[u8]) -> Result<Self, CryptoError> {
        let binding = Binding::from_slice(binding).map_err(CryptoError::InvalidBinding)?;
        Ok(Self::compute(&binding))
    }

    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_SIZE] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidBinding(BindingError),
    PayloadTooLarge { size: usize, max: usize },
    FieldTooLarge { size: usize },
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidNonceLength { expected: usize, actual: usize },
    InvalidCiphertextLength { actual: usize },
    AssociatedDataTooLarge { size: usize, max: usize },
    LengthOverflow,
    CounterOverflow,
    AuthenticationFailed,
    SelfTestFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding(error) => error.fmt(formatter),
            Self::PayloadTooLarge { size, max } => {
                write!(formatter, "runtime payload is too large: {size} > {max}")
            }
            Self::FieldTooLarge { size } => {
                write!(formatter, "framed field is too large: {size} bytes")
            }
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    formatter,
                    "crypto key length is invalid: {actual} != {expected}"
                )
            }
            Self::InvalidNonceLength { expected, actual } => {
                write!(
                    formatter,
                    "crypto nonce length is invalid: {actual} != {expected}"
                )
            }
            Self::InvalidCiphertextLength { actual } => {
                write!(
                    formatter,
                    "GCM ciphertext and tag length is invalid: {actual} bytes"
                )
            }
            Self::AssociatedDataTooLarge { size, max } => {
                write!(
                    formatter,
                    "GCM associated data is too large: {size} > {max}"
                )
            }
            Self::LengthOverflow => {
                formatter.write_str("GCM length does not fit in a 64-bit bit count")
            }
            Self::CounterOverflow => formatter.write_str("GCM counter space is exhausted"),
            Self::AuthenticationFailed => formatter.write_str("GCM authentication failed"),
            Self::SelfTestFailed => formatter.write_str("crypto software self-test failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn authentication_tag(binding_digest: &Digest, payload: &[u8]) -> Result<Digest, CryptoError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(CryptoError::PayloadTooLarge {
            size: payload.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }
    compute_framed(AUTHENTICATION_DOMAIN, &[binding_digest.as_ref(), payload])
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// HMAC-SHA-256 over a sequence of already bounded fields.
///
/// The framing caller owns length validation; this function does not allocate a
/// concatenated secret buffer and wipes its intermediate pads before returning.
pub fn hmac_sha256(key: &[u8], fields: &[&[u8]]) -> Digest {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..DIGEST_SIZE].copy_from_slice(sha256(key).as_ref());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; BLOCK_SIZE];
    let mut outer_pad = [0u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] = key_block[index] ^ 0x36;
        outer_pad[index] = key_block[index] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    for field in fields {
        inner.update(field);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(inner_digest.as_ref());
    let result = outer.finalize();

    key_block.fill(0);
    inner_pad.fill(0);
    outer_pad.fill(0);
    result
}

pub fn hmac_sha256_bytes(key: &[u8], fields: &[&[u8]]) -> [u8; DIGEST_SIZE] {
    hmac_sha256(key, fields).into_bytes()
}

/// AES-128 in CTR mode with a big-endian 128-bit counter.
pub fn aes128_ctr_crypt(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 16,
            actual: key.len(),
        });
    }
    if iv.len() != 16 {
        return Err(CryptoError::InvalidNonceLength {
            expected: 16,
            actual: iv.len(),
        });
    }
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(CryptoError::PayloadTooLarge {
            size: input.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    let cipher = Aes128::new(key)?;
    let mut counter = [0u8; 16];
    counter.copy_from_slice(iv);
    let mut output = vec![0u8; input.len()];
    for (block_index, chunk) in input.chunks(16).enumerate() {
        let mut keystream = counter;
        cipher.encrypt_block(&mut keystream);
        let offset = block_index * 16;
        for (index, byte) in chunk.iter().enumerate() {
            output[offset + index] = *byte ^ keystream[index];
        }
        increment_counter(&mut counter);
        keystream.fill(0);
    }
    counter.fill(0);
    Ok(output)
}

struct Aes128 {
    round_keys: [u32; 44],
}

impl Aes128 {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: key.len(),
            });
        }
        let mut round_keys = [0u32; 44];
        for (index, word) in round_keys[..4].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                key[offset],
                key[offset + 1],
                key[offset + 2],
                key[offset + 3],
            ]);
        }
        for index in 4..44 {
            let mut word = round_keys[index - 1];
            if index % 4 == 0 {
                word = sub_word(word.rotate_left(8)) ^ (u32::from(rcon(index / 4)) << 24);
            }
            round_keys[index] = round_keys[index - 4] ^ word;
        }
        Ok(Self { round_keys })
    }

    fn encrypt_block(&self, state: &mut [u8; 16]) {
        add_round_key(state, &self.round_keys[0..4]);
        for round in 1..10 {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, &self.round_keys[round * 4..round * 4 + 4]);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, &self.round_keys[40..44]);
    }
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        self.round_keys.fill(0);
    }
}

/// AES-256 in CTR mode with a big-endian 128-bit counter, matching the JCA
/// AES/CTR/NoPadding counter convention used by the current R1 resource codec.
pub fn aes256_ctr_crypt(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        });
    }
    if iv.len() != 16 {
        return Err(CryptoError::InvalidNonceLength {
            expected: 16,
            actual: iv.len(),
        });
    }
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(CryptoError::PayloadTooLarge {
            size: input.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    let cipher = Aes256::new(key)?;
    let mut counter = [0u8; 16];
    counter.copy_from_slice(iv);
    let mut output = vec![0u8; input.len()];
    for (block_index, chunk) in input.chunks(16).enumerate() {
        let mut keystream = counter;
        cipher.encrypt_block(&mut keystream);
        let offset = block_index * 16;
        for (index, byte) in chunk.iter().enumerate() {
            output[offset + index] = *byte ^ keystream[index];
        }
        increment_counter(&mut counter);
        keystream.fill(0);
    }
    counter.fill(0);
    Ok(output)
}

struct Aes256 {
    round_keys: [u32; 60],
}

impl Aes256 {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }
        let mut round_keys = [0u32; 60];
        for (index, word) in round_keys[..8].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                key[offset],
                key[offset + 1],
                key[offset + 2],
                key[offset + 3],
            ]);
        }
        for index in 8..60 {
            let mut word = round_keys[index - 1];
            if index % 8 == 0 {
                word = sub_word(word.rotate_left(8)) ^ (u32::from(rcon(index / 8)) << 24);
            } else if index % 8 == 4 {
                word = sub_word(word);
            }
            round_keys[index] = round_keys[index - 8] ^ word;
        }
        Ok(Self { round_keys })
    }

    fn encrypt_block(&self, state: &mut [u8; 16]) {
        add_round_key(state, &self.round_keys[0..4]);
        for round in 1..14 {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, &self.round_keys[round * 4..round * 4 + 4]);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, &self.round_keys[56..60]);
    }
}

impl Drop for Aes256 {
    fn drop(&mut self) {
        self.round_keys.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoCapabilities {
    pub cpu_aes_ni: bool,
    pub cpu_pclmulqdq: bool,
    pub software_aes: bool,
    pub software_ghash: bool,
    pub hardware_aes: bool,
    pub hardware_ghash: bool,
}

impl CryptoCapabilities {
    pub const fn aes_hardware_available(self) -> bool {
        self.hardware_aes
    }

    pub const fn ghash_hardware_available(self) -> bool {
        self.hardware_ghash
    }

    pub const fn software_available(self) -> bool {
        self.software_aes && self.software_ghash
    }
}

type GhashMultiplyFn = fn(&mut [u8; AES_BLOCK_SIZE], &[u8; AES_BLOCK_SIZE]);

static CRYPTO_CAPABILITIES: OnceLock<CryptoCapabilities> = OnceLock::new();
static GHASH_DISPATCH: OnceLock<GhashMultiplyFn> = OnceLock::new();

pub fn crypto_capabilities() -> CryptoCapabilities {
    *CRYPTO_CAPABILITIES.get_or_init(detect_crypto_capabilities)
}

pub fn aes_hardware_available() -> bool {
    crypto_capabilities().hardware_aes
}

pub fn ghash_hardware_available() -> bool {
    crypto_capabilities().hardware_ghash
}

fn detect_crypto_capabilities() -> CryptoCapabilities {
    let supported = supported_runtime_target();
    let (cpu_aes_ni, cpu_pclmulqdq) = if supported {
        detect_cpu_features()
    } else {
        (false, false)
    };
    let (software_aes, software_ghash) = if supported {
        software_backend_self_test()
    } else {
        (false, false)
    };

    // CPU feature bits are reported separately and never promoted to a
    // hardware capability without a verified backend.
    CryptoCapabilities {
        cpu_aes_ni,
        cpu_pclmulqdq,
        software_aes,
        software_ghash,
        hardware_aes: false,
        hardware_ghash: false,
    }
}

const fn supported_runtime_target() -> bool {
    cfg!(all(
        target_arch = "x86_64",
        any(target_os = "windows", target_os = "linux")
    ))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_cpu_features() -> (bool, bool) {
    (
        is_x86_feature_detected!("aes"),
        is_x86_feature_detected!("pclmulqdq"),
    )
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
const fn detect_cpu_features() -> (bool, bool) {
    (false, false)
}

fn software_backend_self_test() -> (bool, bool) {
    let aes_ok = match Aes256::new(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]) {
        Ok(cipher) => {
            let mut block = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ];
            cipher.encrypt_block(&mut block);
            let expected = [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89,
            ];
            let result = block == expected;
            block.fill(0);
            result
        }
        Err(_) => false,
    };

    let mut value = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78,
    ];
    let hash_subkey = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];
    let expected = [
        0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde,
        0xb7,
    ];
    ghash_multiply_software(&mut value, &hash_subkey);
    let ghash_ok = value == expected;
    value.fill(0);
    (aes_ok, ghash_ok && ghash_differential_gate())
}

fn ghash_differential_gate() -> bool {
    let mut left = [0u8; AES_BLOCK_SIZE];
    let mut right = [0u8; AES_BLOCK_SIZE];
    let mut state = 0x9e37_79b9u32;
    let mut success = true;

    for round in 0..16 {
        for byte in &mut left {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        for byte in &mut right {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let mut software = left;
        ghash_multiply_software(&mut software, &right);
        let reference = ghash_multiply_reference(&left, &right);
        success &= software == reference;
        software.fill(0);
        let mut reference = reference;
        reference.fill(0);
        if round == 15 {
            left.fill(0);
            right.fill(0);
        }
    }
    success
}

fn ghash_multiply_reference(
    input: &[u8; AES_BLOCK_SIZE],
    hash_subkey: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let input = u128::from_be_bytes(*input);
    let mut factor = u128::from_be_bytes(*hash_subkey);
    let reduction = 0xe1u128 << 120;
    let mut product = 0u128;
    for bit_index in 0..128 {
        let bit = (input >> (127 - bit_index)) & 1;
        product ^= factor & 0u128.wrapping_sub(bit);
        let least_significant_bit = factor & 1;
        factor = (factor >> 1) ^ (reduction & 0u128.wrapping_sub(least_significant_bit));
    }
    product.to_be_bytes()
}

pub fn ghash_multiply(
    input: &[u8; AES_BLOCK_SIZE],
    hash_subkey: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let mut value = *input;
    ghash_multiply_dispatch(&mut value, hash_subkey);
    value
}

pub fn ghash(
    hash_subkey: &[u8; AES_BLOCK_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; AES_BLOCK_SIZE], CryptoError> {
    validate_gcm_lengths(aad.len(), ciphertext.len())?;
    ensure_software_backend()?;
    let mut workspace = GhashWorkspace::new(hash_subkey);
    workspace.update(aad);
    workspace.update(ciphertext);
    workspace.finish(aad.len(), ciphertext.len())
}

pub fn aes256_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_gcm_inputs(key, nonce, aad.len(), plaintext.len())?;
    ensure_software_backend()?;
    let mut workspace = GcmWorkspace::new(key, nonce, aad)?;
    let output_len = plaintext
        .len()
        .checked_add(GCM_TAG_SIZE)
        .ok_or(CryptoError::LengthOverflow)?;
    let mut output = WipedVec::new(output_len);
    workspace.crypt_payload(plaintext, &mut output.as_mut_slice()[..plaintext.len()])?;
    let mut tag = workspace.tag_for(&output.as_mut_slice()[..plaintext.len()])?;
    output.as_mut_slice()[plaintext.len()..].copy_from_slice(&tag);
    tag.fill(0);
    Ok(output.into_inner())
}

pub fn aes256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext_and_tag.len() < GCM_TAG_SIZE {
        return Err(CryptoError::InvalidCiphertextLength {
            actual: ciphertext_and_tag.len(),
        });
    }
    let ciphertext_len = ciphertext_and_tag.len() - GCM_TAG_SIZE;
    validate_gcm_inputs(key, nonce, aad.len(), ciphertext_len)?;
    ensure_software_backend()?;

    let mut workspace = GcmWorkspace::new(key, nonce, aad)?;
    let mut expected_tag = workspace.tag_for(&ciphertext_and_tag[..ciphertext_len])?;
    let authenticated = constant_time_tag_eq(&expected_tag, &ciphertext_and_tag[ciphertext_len..]);
    expected_tag.fill(0);
    if !authenticated {
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut plaintext = WipedVec::new(ciphertext_len);
    workspace.crypt_payload(
        &ciphertext_and_tag[..ciphertext_len],
        plaintext.as_mut_slice(),
    )?;
    Ok(plaintext.into_inner())
}

fn ensure_software_backend() -> Result<(), CryptoError> {
    if crypto_capabilities().software_available() {
        Ok(())
    } else {
        Err(CryptoError::SelfTestFailed)
    }
}

fn validate_gcm_inputs(
    key: &[u8],
    nonce: &[u8],
    aad_len: usize,
    payload_len: usize,
) -> Result<(), CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        });
    }
    if nonce.len() != GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLength {
            expected: GCM_NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    validate_gcm_lengths(aad_len, payload_len)
}

fn validate_gcm_lengths(aad_len: usize, payload_len: usize) -> Result<(), CryptoError> {
    if aad_len > MAX_PAYLOAD_SIZE {
        return Err(CryptoError::AssociatedDataTooLarge {
            size: aad_len,
            max: MAX_PAYLOAD_SIZE,
        });
    }
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(CryptoError::PayloadTooLarge {
            size: payload_len,
            max: MAX_PAYLOAD_SIZE,
        });
    }
    let payload_blocks = payload_len
        .checked_add(AES_BLOCK_SIZE - 1)
        .ok_or(CryptoError::LengthOverflow)?
        / AES_BLOCK_SIZE;
    if payload_blocks > MAX_GCM_BLOCKS {
        return Err(CryptoError::CounterOverflow);
    }
    bit_length(aad_len)?;
    bit_length(payload_len)?;
    Ok(())
}

fn bit_length(length: usize) -> Result<u64, CryptoError> {
    let length = u64::try_from(length).map_err(|_| CryptoError::LengthOverflow)?;
    length.checked_mul(8).ok_or(CryptoError::LengthOverflow)
}

struct GhashWorkspace {
    state: [u8; AES_BLOCK_SIZE],
    hash_subkey: [u8; AES_BLOCK_SIZE],
    block: [u8; AES_BLOCK_SIZE],
    length_block: [u8; AES_BLOCK_SIZE],
}

impl GhashWorkspace {
    fn new(hash_subkey: &[u8; AES_BLOCK_SIZE]) -> Self {
        Self {
            state: [0; AES_BLOCK_SIZE],
            hash_subkey: *hash_subkey,
            block: [0; AES_BLOCK_SIZE],
            length_block: [0; AES_BLOCK_SIZE],
        }
    }

    fn reset(&mut self) {
        self.state.fill(0);
        self.block.fill(0);
        self.length_block.fill(0);
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(AES_BLOCK_SIZE) {
            self.block.fill(0);
            self.block[..chunk.len()].copy_from_slice(chunk);
            for index in 0..AES_BLOCK_SIZE {
                self.state[index] ^= self.block[index];
            }
            let mut state = self.state;
            ghash_multiply_dispatch(&mut state, &self.hash_subkey);
            self.state = state;
            state.fill(0);
            self.block.fill(0);
        }
    }

    fn finish(
        &mut self,
        aad_len: usize,
        ciphertext_len: usize,
    ) -> Result<[u8; AES_BLOCK_SIZE], CryptoError> {
        self.length_block[..8].copy_from_slice(&bit_length(aad_len)?.to_be_bytes());
        self.length_block[8..].copy_from_slice(&bit_length(ciphertext_len)?.to_be_bytes());
        for index in 0..AES_BLOCK_SIZE {
            self.state[index] ^= self.length_block[index];
        }
        let mut state = self.state;
        ghash_multiply_dispatch(&mut state, &self.hash_subkey);
        self.state = state;
        state.fill(0);
        Ok(self.state)
    }
}

impl Drop for GhashWorkspace {
    fn drop(&mut self) {
        self.state.fill(0);
        self.hash_subkey.fill(0);
        self.block.fill(0);
        self.length_block.fill(0);
    }
}

struct WipedVec(Vec<u8>);

impl WipedVec {
    fn new(length: usize) -> Self {
        Self(vec![0; length])
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn into_inner(self) -> Vec<u8> {
        let mut output = Vec::new();
        let mut owned = self;
        std::mem::swap(&mut output, &mut owned.0);
        std::mem::forget(owned);
        output
    }
}

impl Drop for WipedVec {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct GcmWorkspace {
    cipher: Aes256,
    nonce: [u8; GCM_NONCE_SIZE],
    aad: Vec<u8>,
    j0: [u8; AES_BLOCK_SIZE],
    counter: [u8; AES_BLOCK_SIZE],
    tag_mask: [u8; AES_BLOCK_SIZE],
    calculated_tag: [u8; AES_BLOCK_SIZE],
    keystream: [u8; AES_BLOCK_SIZE],
    ghash: GhashWorkspace,
}

impl GcmWorkspace {
    fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Self, CryptoError> {
        let cipher = Aes256::new(key)?;
        let mut nonce_copy = [0u8; GCM_NONCE_SIZE];
        nonce_copy.copy_from_slice(nonce);
        let aad_copy = aad.to_vec();

        let mut hash_subkey = [0u8; AES_BLOCK_SIZE];
        cipher.encrypt_block(&mut hash_subkey);
        let ghash = GhashWorkspace::new(&hash_subkey);
        hash_subkey.fill(0);

        let mut j0 = [0u8; AES_BLOCK_SIZE];
        j0[..GCM_NONCE_SIZE].copy_from_slice(&nonce_copy);
        j0[AES_BLOCK_SIZE - 1] = 1;
        let mut tag_mask = j0;
        cipher.encrypt_block(&mut tag_mask);

        Ok(Self {
            cipher,
            nonce: nonce_copy,
            aad: aad_copy,
            j0,
            counter: j0,
            tag_mask,
            calculated_tag: [0; AES_BLOCK_SIZE],
            keystream: [0; AES_BLOCK_SIZE],
            ghash,
        })
    }

    fn crypt_payload(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        if input.len() != output.len() {
            return Err(CryptoError::InvalidCiphertextLength {
                actual: input.len(),
            });
        }
        self.counter = self.j0;
        for (block_index, chunk) in input.chunks(AES_BLOCK_SIZE).enumerate() {
            increment_gcm_counter(&mut self.counter);
            self.keystream = self.counter;
            self.cipher.encrypt_block(&mut self.keystream);
            let offset = block_index * AES_BLOCK_SIZE;
            for (index, byte) in chunk.iter().enumerate() {
                output[offset + index] = *byte ^ self.keystream[index];
            }
            self.keystream.fill(0);
        }
        Ok(())
    }

    fn tag_for(&mut self, ciphertext: &[u8]) -> Result<[u8; GCM_TAG_SIZE], CryptoError> {
        self.ghash.reset();
        self.ghash.update(&self.aad);
        self.ghash.update(ciphertext);
        let state = self.ghash.finish(self.aad.len(), ciphertext.len())?;
        for (index, calculated) in self.calculated_tag.iter_mut().enumerate() {
            *calculated = self.tag_mask[index] ^ state[index];
        }
        Ok(self.calculated_tag)
    }
}

impl Drop for GcmWorkspace {
    fn drop(&mut self) {
        self.nonce.fill(0);
        self.aad.fill(0);
        self.j0.fill(0);
        self.counter.fill(0);
        self.tag_mask.fill(0);
        self.calculated_tag.fill(0);
        self.keystream.fill(0);
    }
}

fn constant_time_tag_eq(expected: &[u8; GCM_TAG_SIZE], actual: &[u8]) -> bool {
    if actual.len() != GCM_TAG_SIZE {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..GCM_TAG_SIZE {
        difference |= expected[index] ^ actual[index];
    }
    difference == 0
}

fn ghash_multiply_dispatch(value: &mut [u8; AES_BLOCK_SIZE], hash_subkey: &[u8; AES_BLOCK_SIZE]) {
    let multiply = GHASH_DISPATCH.get_or_init(|| {
        let _ = crypto_capabilities();
        ghash_multiply_software
    });
    multiply(value, hash_subkey);
}

fn ghash_multiply_software(value: &mut [u8; AES_BLOCK_SIZE], hash_subkey: &[u8; AES_BLOCK_SIZE]) {
    let mut input = *value;
    let mut product = [0u8; AES_BLOCK_SIZE];
    let mut factor = *hash_subkey;

    for bit_index in 0..128 {
        let bit = (input[bit_index / 8] >> (7 - (bit_index & 7))) & 1;
        let mask = 0u8.wrapping_sub(bit);
        for index in 0..AES_BLOCK_SIZE {
            product[index] ^= factor[index] & mask;
        }

        let least_significant_bit = factor[AES_BLOCK_SIZE - 1] & 1;
        let mut carry = 0u8;
        for byte in &mut factor {
            let value = *byte;
            *byte = (value >> 1) | carry;
            carry = (value & 1) << 7;
        }
        factor[0] ^= 0xe1 & 0u8.wrapping_sub(least_significant_bit);
    }

    *value = product;
    input.fill(0);
    product.fill(0);
    factor.fill(0);
}

fn increment_gcm_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    let (last, carry_last) = counter[15].overflowing_add(1);
    let (third, carry_third) = counter[14].overflowing_add(carry_last as u8);
    let (second, carry_second) = counter[13].overflowing_add(carry_third as u8);
    let (first, _) = counter[12].overflowing_add(carry_second as u8);
    counter[12] = first;
    counter[13] = second;
    counter[14] = third;
    counter[15] = last;
}

fn increment_counter(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
}

fn add_round_key(state: &mut [u8; 16], words: &[u32]) {
    for (column, word) in words.iter().enumerate() {
        let key = word.to_be_bytes();
        let offset = column * 4;
        for index in 0..4 {
            state[offset + index] ^= key[index];
        }
    }
}

fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        aes_sbox(bytes[0]),
        aes_sbox(bytes[1]),
        aes_sbox(bytes[2]),
        aes_sbox(bytes[3]),
    ])
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = aes_sbox(*byte);
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let original = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[column * 4 + row] = original[((column + row) & 3) * 4 + row];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let offset = column * 4;
        let a0 = state[offset];
        let a1 = state[offset + 1];
        let a2 = state[offset + 2];
        let a3 = state[offset + 3];
        state[offset] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[offset + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[offset + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[offset + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

fn rcon(round: usize) -> u8 {
    let mut value = 1u8;
    for _ in 1..round {
        value = gf_mul(value, 2);
    }
    value
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        let bit_mask = 0u8.wrapping_sub(right & 1);
        result ^= left & bit_mask;
        let high_bit = left >> 7;
        left <<= 1;
        left ^= 0x1b & 0u8.wrapping_sub(high_bit);
        right >>= 1;
    }
    result
}

fn aes_sbox(value: u8) -> u8 {
    let mut inverse = 1u8;
    for bit in (0..8).rev() {
        inverse = gf_mul(inverse, inverse);
        let product = gf_mul(inverse, value);
        let bit_mask = 0u8.wrapping_sub(((254u16 >> bit) & 1) as u8);
        inverse = (product & bit_mask) | (inverse & !bit_mask);
    }
    let non_zero = (value | value.wrapping_neg()) >> 7;
    inverse &= 0u8.wrapping_sub(non_zero);
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

fn compute_framed(domain: &[u8], fields: &[&[u8]]) -> Result<Digest, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_| CryptoError::FieldTooLarge { size: field.len() })?;
        hasher.update(&length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize())
}

fn transform(state: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    let mut words = [0u32; 64];
    for (index, word) in words[..16].iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }

    let mut working = *state;
    for index in 0..64 {
        let s1 =
            working[4].rotate_right(6) ^ working[4].rotate_right(11) ^ working[4].rotate_right(25);
        let choice = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
        let temp1 = working[7]
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(K[index])
            .wrapping_add(words[index]);
        let s0 =
            working[0].rotate_right(2) ^ working[0].rotate_right(13) ^ working[0].rotate_right(22);
        let majority =
            (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
        let temp2 = s0.wrapping_add(majority);
        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3].wrapping_add(temp1);
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = temp1.wrapping_add(temp2);
    }
    for (destination, source) in state.iter_mut().zip(working) {
        *destination = destination.wrapping_add(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex high");
                let low = (pair[1] as char).to_digit(16).expect("hex low");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(sha256(b"").as_ref()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc").as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut hasher = Sha256::new();
        hasher.update(&vec![b'a'; 1000]);
        assert_eq!(
            hex(hasher.finalize().as_ref()),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn binding_digest_is_domain_separated_and_deterministic() {
        let binding = Binding::from_slice(b"binding").expect("binding");
        let first = RuntimeBindingDigest::compute(&binding);
        let second = RuntimeBindingDigest::compute(&binding);
        assert_eq!(first, second);
        assert_eq!(
            RuntimeBindingDigest::compute_bytes(b"binding").expect("binding"),
            first
        );
        assert_eq!(
            hex(first.as_bytes()),
            "611e402b187c76217b735b5a28eb713929647213ca597fa26bf537c41450fee4"
        );
        assert_ne!(first.as_bytes(), sha256(binding.as_bytes()).as_ref());
        assert_ne!(
            first,
            RuntimeBindingDigest::compute(&Binding::from_slice(b"other").expect("binding"))
        );
    }

    #[test]
    fn authentication_tag_is_framed_and_constant_time() {
        let digest = sha256(b"binding");
        let tag = authentication_tag(&digest, b"payload").expect("tag");
        assert!(constant_time_eq(tag.as_ref(), tag.as_ref()));
        assert!(!constant_time_eq(tag.as_ref(), &[0; DIGEST_SIZE]));
        assert_eq!(
            hex(tag.as_ref()),
            "37f74cde6f51b07db51c83a73133b68ed0d14454a61b3310576c420be948b34a"
        );
        assert_ne!(tag, authentication_tag(&digest, b"payload2").expect("tag"));
    }

    #[test]
    fn hmac_sha256_and_aes256_match_known_vectors() {
        assert_eq!(
            hex(hmac_sha256(b"key", &[b"The quick brown fox jumps over the lazy dog"],).as_ref()),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );

        let aes128_key = decode_hex("000102030405060708090a0b0c0d0e0f");
        let mut aes128_block = decode_hex("00112233445566778899aabbccddeeff")
            .try_into()
            .expect("AES-128 block");
        let aes128 = Aes128::new(&aes128_key).expect("AES-128 key");
        aes128.encrypt_block(&mut aes128_block);
        assert_eq!(hex(&aes128_block), "69c4e0d86a7b0430d8cdb78070b4c55a");

        let key = decode_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut block = decode_hex("00112233445566778899aabbccddeeff")
            .try_into()
            .expect("AES-256 block");
        let cipher = Aes256::new(&key).expect("AES-256 key");
        cipher.encrypt_block(&mut block);
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");

        let iv = [0u8; 16];
        let plaintext = b"secret resource bytes";
        let encrypted = aes256_ctr_crypt(&key, &iv, plaintext).expect("encrypt");
        assert_ne!(encrypted, plaintext);
        assert_eq!(
            aes256_ctr_crypt(&key, &iv, &encrypted).expect("decrypt"),
            plaintext
        );

        let ctr_key =
            decode_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let ctr_iv = decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ctr_plaintext = decode_hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ));
        let ctr_expected = decode_hex(concat!(
            "601ec313775789a5b7a7f504bbf3d228",
            "f443e3ca4d62b59aca84e990cacaf5c5",
            "2b0930daa23de94ce87017ba2d84988d",
            "dfc9c58db67aada613c2dd08457941a6",
        ));
        assert_eq!(
            aes256_ctr_crypt(&ctr_key, &ctr_iv, &ctr_plaintext).expect("CTR vector"),
            ctr_expected
        );
    }

    #[test]
    fn aes256_gcm_matches_nist_vector_and_round_trips() {
        if !supported_runtime_target() {
            assert_eq!(
                aes256_gcm_encrypt(&[0; 32], &[0; GCM_NONCE_SIZE], &[], &[]),
                Err(CryptoError::SelfTestFailed)
            );
            return;
        }
        let key = decode_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = decode_hex("cafebabefacedbaddecaf888");
        let aad = decode_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = decode_hex(concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b391aafd255",
        ));
        let expected = decode_hex(concat!(
            "522dc1f099567d07f47f37a32a84427d",
            "643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838",
            "c5f61e6393ba7a0abcc9f662898015ad",
            "2df7cd675b4f09163b41ebf980a7f638",
        ));
        let sealed = aes256_gcm_encrypt(&key, &nonce, &aad, &plaintext).expect("GCM encrypt");
        assert_eq!(sealed, expected);
        assert_eq!(
            aes256_gcm_decrypt(&key, &nonce, &aad, &sealed).expect("GCM decrypt"),
            plaintext
        );
    }

    #[test]
    fn aes256_gcm_empty_vector_and_authentication_failures() {
        if !supported_runtime_target() {
            assert_eq!(
                aes256_gcm_encrypt(&[0; 32], &[0; GCM_NONCE_SIZE], &[], &[]),
                Err(CryptoError::SelfTestFailed)
            );
            return;
        }
        let key = [0u8; 32];
        let nonce = [0u8; GCM_NONCE_SIZE];
        let expected = decode_hex("530f8afbc74536b9a963b4f1c4cb738b");
        let sealed = aes256_gcm_encrypt(&key, &nonce, &[], &[]).expect("empty GCM encrypt");
        assert_eq!(sealed, expected);
        assert_eq!(
            aes256_gcm_decrypt(&key, &nonce, &[], &sealed).expect("empty GCM decrypt"),
            Vec::<u8>::new()
        );

        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert_eq!(
            aes256_gcm_decrypt(&key, &nonce, &[], &tampered),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            aes256_gcm_decrypt(&key, &nonce, b"aad", &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            aes256_gcm_decrypt(&key, &[1u8; GCM_NONCE_SIZE], &[], &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
        assert!(matches!(
            aes256_gcm_decrypt(&key, &nonce, &[], &[0u8; GCM_TAG_SIZE - 1]),
            Err(CryptoError::InvalidCiphertextLength { .. })
        ));
    }

    #[test]
    fn ghash_and_capability_gate_match_known_answers() {
        let input: [u8; AES_BLOCK_SIZE] = decode_hex("0388dace60b6a392f328c2b971b2fe78")
            .try_into()
            .expect("GHASH input");
        let hash_subkey: [u8; AES_BLOCK_SIZE] = decode_hex("66e94bd4ef8a2c3b884cfa59ca342b2e")
            .try_into()
            .expect("GHASH H");
        assert_eq!(
            hex(&ghash_multiply(&input, &hash_subkey)),
            "5e2ec746917062882c85b0685353deb7"
        );
        let capabilities = crypto_capabilities();
        assert_eq!(capabilities.software_aes, supported_runtime_target());
        assert_eq!(capabilities.software_ghash, supported_runtime_target());
        if !supported_runtime_target() {
            assert!(!capabilities.cpu_aes_ni);
            assert!(!capabilities.cpu_pclmulqdq);
        }
        assert!(!capabilities.hardware_aes);
        assert!(!capabilities.hardware_ghash);
        assert!(!aes_hardware_available());
        assert!(!ghash_hardware_available());
    }

    #[test]
    fn public_helpers_enforce_the_kotlin_r1_bounds() {
        assert_eq!(
            RuntimeBindingDigest::compute_bytes(&[]),
            Err(CryptoError::InvalidBinding(BindingError::Empty)),
        );
        assert!(matches!(
            RuntimeBindingDigest::compute_bytes(&vec![0; MAX_BINDING_SIZE + 1]),
            Err(CryptoError::InvalidBinding(BindingError::TooLarge { .. }))
        ));
        assert!(matches!(
            authentication_tag(&sha256(b"binding"), &vec![0; MAX_PAYLOAD_SIZE + 1]),
            Err(CryptoError::PayloadTooLarge { .. })
        ));
        assert!(matches!(
            aes256_gcm_encrypt(&[0; 31], &[0; GCM_NONCE_SIZE], &[], &[]),
            Err(CryptoError::InvalidKeyLength { .. })
        ));
        assert!(matches!(
            aes256_gcm_encrypt(&[0; 32], &[0; GCM_NONCE_SIZE - 1], &[], &[]),
            Err(CryptoError::InvalidNonceLength { .. })
        ));
    }
}
