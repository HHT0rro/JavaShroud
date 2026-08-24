#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

//! Safe, standalone AKEN-R1 page wire support.
//!
//! The byte layouts in this crate intentionally mirror the current Kotlin
//! implementation. Parsers are bounded and strict: one parser consumes one
//! complete value and rejects truncation, unsupported values, concatenation,
//! reordering, and trailing bytes.

mod directory;
mod frame;
pub use directory::{
    decode_directory, encode_directory, ArtifactDirectory, ArtifactDirectoryEntry,
    DirectoryRuntimeBinding, DIRECTORY_MAGIC, PAGE_KEY_SIZE,
};
pub use frame::{
    AuthenticatedFrame as EnvelopeFrame, FrameWriter, ProtocolError, RuntimeEnvelope,
    AUTH_TAG_SIZE, MAX_FRAME_SIZE,
};

use jsrt_crypto::{Binding, BindingError};
use std::fmt;
use std::ops::Range;

pub type Digest = [u8; 32];

pub const DIGEST_SIZE: usize = 32;
pub const ENCODED_HANDLE_SIZE: usize = 24;
pub const LOCATOR_TOKEN_SIZE: usize = 16;
pub const FINGERPRINT_SIZE: usize = 32;

pub const MAX_BINDING_SIZE: usize = 4 * 1024;
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_PAGE_PLAINTEXT_SIZE: usize = MAX_PAYLOAD_SIZE;
pub const MAX_CALL_SITE_PROOF_SIZE: usize = 4096;
pub const MAX_LOGICAL_IDENTITY_SIZE: usize = 64 * 1024;
pub const MAX_LEAF_IDENTITY_ENCODING_SIZE: usize = 96 * 1024;
pub const MAX_RESOURCE_PATH_SIZE: usize = 4096;
pub const MAX_VARIANT_SIZE: usize = 256;
pub const MAX_MERKLE_DEPTH: usize = 64;
pub const MAX_ROUTE_ENCODING_SIZE: usize = 128 * 1024;
pub const MAX_PROOF_ENCODING_SIZE: usize = 160 * 1024;
pub const MAX_EVALUATOR_OPAQUE_SIZE: usize = 131_035;
pub const MAX_EVALUATOR_PLAN_ENCODING_SIZE: usize = 128 * 1024;
pub const MAX_DESCRIPTOR_ENCODING_SIZE: usize = 384 * 1024;
pub const MAX_ENVELOPE_SIZE: usize = 4096;
pub const MAX_AAD_SIZE: usize = 80 * 1024;
pub const MAX_PAGE_FRAME_SIZE: usize = MAX_PAGE_PLAINTEXT_SIZE + 1024;
pub const MAX_PAGE_KEY_SIZE: usize = 128;

pub const LOGICAL_HEADER_SIZE: usize = 201;
pub const GCM_TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const OFFSET_KIND: usize = 0;
pub const OFFSET_PAGE_INDEX: usize = 1;
pub const OFFSET_PLAINTEXT_LENGTH: usize = 5;
pub const OFFSET_NONCE: usize = 9;
pub const OFFSET_COMMITMENT: usize = 21;
pub const OFFSET_IDENTITY_HASH: usize = 53;
pub const OFFSET_EVALUATOR_FINGERPRINT: usize = 85;
pub const OFFSET_CODEC_HASH: usize = 117;
pub const OFFSET_LAYOUT_HASH: usize = 149;
pub const OFFSET_LOCATOR: usize = 181;
pub const OFFSET_CIPHERTEXT_LENGTH: usize = 197;
pub const CANONICAL_CODEC_VARIANT: &str = "aes-256-gcm";

pub const R1_MAGIC: [u8; 4] = *b"JSR1";
pub const R1_VERSION: u8 = 1;
pub const R1_AUTH_TAG_SIZE: usize = DIGEST_SIZE;
pub const R1_HEADER_SIZE: usize = 4 + 1 + 4 + DIGEST_SIZE;
pub const R1_MIN_FRAME_SIZE: usize = R1_HEADER_SIZE + R1_AUTH_TAG_SIZE;
pub const R1_MAX_FRAME_SIZE: usize = R1_MIN_FRAME_SIZE + MAX_PAYLOAD_SIZE;

const PAGE_AAD_DOMAIN: &[u8] = b"page-aad";
const DESCRIPTOR_BINDING_DOMAIN: &[u8] = b"page-envelope-descriptor";
const CALL_SITE_BINDING_DOMAIN: &[u8] = b"page-envelope-call-site";
const ROUTE_BINDING_DOMAIN: &[u8] = b"page-envelope-route";
const ENVELOPE_BINDING_DOMAIN: &[u8] = b"page-envelope";
const PROOF_BINDING_DOMAIN: &[u8] = b"page-proof";
const HEADER_BINDING_DOMAIN: &[u8] = b"page-header";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageError {
    Truncated {
        offset: usize,
        requested: usize,
        remaining: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    LengthTooLarge {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidInput(&'static str),
    InvalidKind(u8),
    InvalidPageIndex(i32),
    InvalidUtf8(&'static str),
    InvalidPath(&'static str),
    InvalidVariant(&'static str),
    InvalidDirection(u8),
    InvalidHandleLength {
        field: &'static str,
        actual: usize,
    },
    InvalidState(&'static str),
    DuplicatePageKey,
    HashMismatch(&'static str),
    BindingMismatch(&'static str),
    AuthenticationFailed,
    UnsupportedVersion(u8),
    InvalidMagic,
    InvalidForm(u8),
    InvalidCiphertextLength,
    NotFound,
}

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                offset,
                requested,
                remaining,
            } => write!(
                f,
                "wire input truncated at {offset}: requested {requested}, {remaining} remain"
            ),
            Self::TrailingBytes { remaining } => {
                write!(f, "wire input has {remaining} trailing bytes")
            }
            Self::LengthTooLarge {
                field,
                length,
                maximum,
            } => write!(f, "{field} length {length} exceeds bound {maximum}"),
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(f, "{field} length {actual} does not equal {expected}"),
            Self::InvalidInput(message) => f.write_str(message),
            Self::InvalidKind(kind) => write!(f, "invalid page kind id {kind}"),
            Self::InvalidPageIndex(index) => write!(f, "invalid page index {index}"),
            Self::InvalidUtf8(field) => write!(f, "{field} is not UTF-8"),
            Self::InvalidPath(field) => write!(f, "{field} is not a normalized relative path"),
            Self::InvalidVariant(field) => write!(f, "{field} variant is invalid"),
            Self::InvalidDirection(direction) => write!(f, "invalid proof direction {direction}"),
            Self::InvalidHandleLength { field, actual } => {
                write!(f, "{field} has invalid length {actual}")
            }
            Self::InvalidState(message) => f.write_str(message),
            Self::DuplicatePageKey => f.write_str("duplicate page key"),
            Self::HashMismatch(field) => write!(f, "{field} hash does not match"),
            Self::BindingMismatch(field) => write!(f, "{field} binding does not match"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported version {version}"),
            Self::InvalidMagic => f.write_str("invalid magic"),
            Self::InvalidForm(form) => write!(f, "invalid envelope form {form}"),
            Self::InvalidCiphertextLength => f.write_str("invalid ciphertext length"),
            Self::NotFound => f.write_str("page key was not found"),
        }
    }
}

impl std::error::Error for PageError {}

/// Explicitly bounded big-endian reader shared by every page parser.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub const fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    pub fn read_u8(&mut self) -> Result<u8, PageError> {
        let range = self.require(1)?;
        self.position += 1;
        Ok(self.bytes[range.start])
    }

    pub fn read_i32_be(&mut self) -> Result<i32, PageError> {
        let range = self.require(4)?;
        self.position += 4;
        Ok(i32::from_be_bytes([
            self.bytes[range.start],
            self.bytes[range.start + 1],
            self.bytes[range.start + 2],
            self.bytes[range.start + 3],
        ]))
    }

    pub fn read_u32_be(&mut self) -> Result<u32, PageError> {
        let range = self.require(4)?;
        self.position += 4;
        Ok(u32::from_be_bytes([
            self.bytes[range.start],
            self.bytes[range.start + 1],
            self.bytes[range.start + 2],
            self.bytes[range.start + 3],
        ]))
    }

    pub fn read_i64_be(&mut self) -> Result<i64, PageError> {
        let range = self.require(8)?;
        self.position += 8;
        Ok(i64::from_be_bytes([
            self.bytes[range.start],
            self.bytes[range.start + 1],
            self.bytes[range.start + 2],
            self.bytes[range.start + 3],
            self.bytes[range.start + 4],
            self.bytes[range.start + 5],
            self.bytes[range.start + 6],
            self.bytes[range.start + 7],
        ]))
    }

    pub fn read_fixed(&mut self, length: usize) -> Result<Vec<u8>, PageError> {
        let range = self.require(length)?;
        self.position += length;
        Ok(self.bytes[range].to_vec())
    }

    pub fn read_frame(
        &mut self,
        maximum_length: usize,
        allow_empty: bool,
        field: &'static str,
    ) -> Result<Vec<u8>, PageError> {
        let length = self.read_u32_be()? as usize;
        if length > maximum_length || (!allow_empty && length == 0) {
            return if length > maximum_length {
                Err(PageError::LengthTooLarge {
                    field,
                    length,
                    maximum: maximum_length,
                })
            } else {
                Err(PageError::InvalidInput(field))
            };
        }
        self.read_fixed(length)
    }

    pub fn skip(&mut self, length: usize) -> Result<(), PageError> {
        self.require(length)?;
        self.position += length;
        Ok(())
    }

    pub fn require_empty(&self) -> Result<(), PageError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(PageError::TrailingBytes {
                remaining: self.remaining(),
            })
        }
    }

    fn require(&self, length: usize) -> Result<Range<usize>, PageError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(PageError::Truncated {
                offset: self.position,
                requested: length,
                remaining,
            });
        }
        Ok(self.position..self.position + length)
    }
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Writer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), PageError> {
        let requested =
            self.bytes
                .len()
                .checked_add(bytes.len())
                .ok_or(PageError::LengthTooLarge {
                    field: "wire",
                    length: usize::MAX,
                    maximum: self.maximum,
                })?;
        if requested > self.maximum {
            return Err(PageError::LengthTooLarge {
                field: "wire",
                length: requested,
                maximum: self.maximum,
            });
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), PageError> {
        self.write(&[value])
    }

    fn write_i32(&mut self, value: i32) -> Result<(), PageError> {
        self.write(&value.to_be_bytes())
    }

    fn write_i64(&mut self, value: i64) -> Result<(), PageError> {
        self.write(&value.to_be_bytes())
    }

    fn write_frame(&mut self, bytes: &[u8], field: &'static str) -> Result<(), PageError> {
        let length = u32::try_from(bytes.len()).map_err(|_| PageError::LengthTooLarge {
            field,
            length: bytes.len(),
            maximum: u32::MAX as usize,
        })?;
        self.write(&length.to_be_bytes())?;
        self.write(bytes)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn copy_fixed<const N: usize>(bytes: &[u8], field: &'static str) -> Result<[u8; N], PageError> {
    if bytes.len() != N {
        return Err(PageError::InvalidLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut result = [0u8; N];
    result.copy_from_slice(bytes);
    Ok(result)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

pub fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    constant_time_eq(left, right)
}

fn hash_domain_framed(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(&(field.len() as u32).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize()
}

const SHA256_K: [u32; 64] = [
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

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
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
            buffer: [0; 64],
            buffered: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.bit_len = self
            .bit_len
            .wrapping_add((bytes.len() as u64).wrapping_mul(8));
        let mut input = bytes;
        while !input.is_empty() {
            let take = (64 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == 64 {
                sha256_transform(&mut self.state, &self.buffer);
                self.buffered = 0;
            }
        }
    }

    fn finalize(mut self) -> Digest {
        let original_bit_len = self.bit_len;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            sha256_transform(&mut self.state, &self.buffer);
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&original_bit_len.to_be_bytes());
        sha256_transform(&mut self.state, &self.buffer);
        let mut output = [0u8; DIGEST_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
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
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize()
}

fn sha256_transform(state: &mut [u32; 8], block: &[u8; 64]) {
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
            .wrapping_add(SHA256_K[index])
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

struct Aes256 {
    round_keys: [u32; 60],
}

impl Aes256 {
    fn new(key: &[u8]) -> Result<Self, PageError> {
        if key.len() != 32 {
            return Err(PageError::InvalidLength {
                field: "AES-256 key",
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

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[0..4]);
        for round in 1..14 {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round * 4..round * 4 + 4]);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, &self.round_keys[56..60]);
    }
}

impl Drop for Aes256 {
    fn drop(&mut self) {
        self.round_keys.fill(0);
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
        state[offset] = gf_mul_byte(a0, 2) ^ gf_mul_byte(a1, 3) ^ a2 ^ a3;
        state[offset + 1] = a0 ^ gf_mul_byte(a1, 2) ^ gf_mul_byte(a2, 3) ^ a3;
        state[offset + 2] = a0 ^ a1 ^ gf_mul_byte(a2, 2) ^ gf_mul_byte(a3, 3);
        state[offset + 3] = gf_mul_byte(a0, 3) ^ a1 ^ a2 ^ gf_mul_byte(a3, 2);
    }
}

fn rcon(round: usize) -> u8 {
    let mut value = 1u8;
    for _ in 1..round {
        value = gf_mul_byte(value, 2);
    }
    value
}

fn gf_mul_byte(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(right & 1);
        result ^= left & mask;
        let high = left >> 7;
        left <<= 1;
        left ^= 0x1b & 0u8.wrapping_sub(high);
        right >>= 1;
    }
    result
}

fn aes_sbox(value: u8) -> u8 {
    let mut inverse = 1u8;
    for bit in (0..8).rev() {
        inverse = gf_mul_byte(inverse, inverse);
        let product = gf_mul_byte(inverse, value);
        let mask = 0u8.wrapping_sub(((254u16 >> bit) & 1) as u8);
        inverse = (product & mask) | (inverse & !mask);
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

fn inc32(counter: &mut [u8; 16]) {
    for index in (12..16).rev() {
        let (value, carry) = counter[index].overflowing_add(1);
        counter[index] = value;
        if !carry {
            break;
        }
    }
}

fn ctr_crypt(cipher: &Aes256, j0: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut counter = *j0;
    let mut output = vec![0u8; input.len()];
    for (block_index, chunk) in input.chunks(16).enumerate() {
        inc32(&mut counter);
        let mut stream = counter;
        cipher.encrypt_block(&mut stream);
        let offset = block_index * 16;
        for (index, byte) in chunk.iter().enumerate() {
            output[offset + index] = *byte ^ stream[index];
        }
        stream.fill(0);
    }
    counter.fill(0);
    output
}

fn ghash_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for byte in x {
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 == 1 {
                for index in 0..16 {
                    z[index] ^= v[index];
                }
            }
            let lsb = v[15] & 1;
            let mut carry = 0u8;
            for value in &mut v {
                let next = *value;
                *value = (next >> 1) | carry;
                carry = (next & 1) << 7;
            }
            if lsb != 0 {
                v[0] ^= 0xe1;
            }
        }
    }
    v.fill(0);
    z
}

fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for input in [aad, ciphertext] {
        for chunk in input.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for index in 0..16 {
                y[index] ^= block[index];
            }
            let next = ghash_mul(&y, h);
            y = next;
            block.fill(0);
        }
    }
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&((aad.len() as u64).wrapping_mul(8)).to_be_bytes());
    lengths[8..].copy_from_slice(&((ciphertext.len() as u64).wrapping_mul(8)).to_be_bytes());
    for index in 0..16 {
        y[index] ^= lengths[index];
    }
    let result = ghash_mul(&y, h);
    y.fill(0);
    lengths.fill(0);
    result
}

fn gcm_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, PageError> {
    if nonce.len() != NONCE_SIZE {
        return Err(PageError::InvalidLength {
            field: "GCM nonce",
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    if plain.len() > MAX_PAGE_PLAINTEXT_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "page plaintext",
            length: plain.len(),
            maximum: MAX_PAGE_PLAINTEXT_SIZE,
        });
    }
    let cipher = Aes256::new(key)?;
    let mut h = [0u8; 16];
    cipher.encrypt_block(&mut h);
    let mut j0 = [0u8; 16];
    j0[..NONCE_SIZE].copy_from_slice(nonce);
    j0[15] = 1;
    let ciphertext = ctr_crypt(&cipher, &j0, plain);
    let mut s = ghash(&h, aad, &ciphertext);
    let mut tag_mask = j0;
    cipher.encrypt_block(&mut tag_mask);
    for index in 0..16 {
        s[index] ^= tag_mask[index];
    }
    let mut result = Vec::with_capacity(ciphertext.len() + GCM_TAG_SIZE);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&s);
    h.fill(0);
    j0.fill(0);
    s.fill(0);
    tag_mask.fill(0);
    let mut ciphertext = ciphertext;
    ciphertext.fill(0);
    Ok(result)
}

fn gcm_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], body: &[u8]) -> Result<Vec<u8>, PageError> {
    if body.len() < GCM_TAG_SIZE {
        return Err(PageError::InvalidCiphertextLength);
    }
    if body.len() > MAX_PAGE_PLAINTEXT_SIZE + GCM_TAG_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "page ciphertext",
            length: body.len(),
            maximum: MAX_PAGE_PLAINTEXT_SIZE + GCM_TAG_SIZE,
        });
    }
    if nonce.len() != NONCE_SIZE {
        return Err(PageError::InvalidLength {
            field: "GCM nonce",
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    let ciphertext = &body[..body.len() - GCM_TAG_SIZE];
    let supplied_tag = &body[body.len() - GCM_TAG_SIZE..];
    let cipher = Aes256::new(key)?;
    let mut h = [0u8; 16];
    cipher.encrypt_block(&mut h);
    let mut j0 = [0u8; 16];
    j0[..NONCE_SIZE].copy_from_slice(nonce);
    j0[15] = 1;
    let mut expected_tag = ghash(&h, aad, ciphertext);
    let mut tag_mask = j0;
    cipher.encrypt_block(&mut tag_mask);
    for index in 0..GCM_TAG_SIZE {
        expected_tag[index] ^= tag_mask[index];
    }
    let authenticated = constant_time_eq(&expected_tag, supplied_tag);
    h.fill(0);
    tag_mask.fill(0);
    if !authenticated {
        j0.fill(0);
        expected_tag.fill(0);
        return Err(PageError::AuthenticationFailed);
    }
    let plain = ctr_crypt(&cipher, &j0, ciphertext);
    j0.fill(0);
    expected_tag.fill(0);
    Ok(plain)
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PageKind {
    Vbc4Method = 1,
    StringPage = 2,
    EncryptedClassPage = 3,
    NativeChunk = 4,
}

impl PageKind {
    pub const fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Result<Self, PageError> {
        match id {
            1 => Ok(Self::Vbc4Method),
            2 => Ok(Self::StringPage),
            3 => Ok(Self::EncryptedClassPage),
            4 => Ok(Self::NativeChunk),
            other => Err(PageError::InvalidKind(other)),
        }
    }

    pub const fn logical_name(self) -> &'static str {
        match self {
            Self::Vbc4Method => "vbc4-method",
            Self::StringPage => "string-page",
            Self::EncryptedClassPage => "encrypted-class-page",
            Self::NativeChunk => "native-chunk",
        }
    }

    #[allow(non_upper_case_globals)]
    pub const Vm: Self = Self::Vbc4Method;
    #[allow(non_upper_case_globals)]
    pub const String: Self = Self::StringPage;
    #[allow(non_upper_case_globals)]
    pub const Class: Self = Self::EncryptedClassPage;
    #[allow(non_upper_case_globals)]
    pub const Native: Self = Self::NativeChunk;
}

pub type AkenResourceKind = PageKind;
pub type ResourceKind = PageKind;

#[derive(Eq, PartialEq, Hash)]
pub struct PageHandle {
    kind: PageKind,
    page_index: i32,
    encoded: [u8; ENCODED_HANDLE_SIZE],
    locator: [u8; LOCATOR_TOKEN_SIZE],
    fingerprint: Digest,
}

impl PageHandle {
    pub fn new(
        kind: PageKind,
        page_index: i32,
        encoded: [u8; ENCODED_HANDLE_SIZE],
        locator: [u8; LOCATOR_TOKEN_SIZE],
        fingerprint: Digest,
    ) -> Result<Self, PageError> {
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        Ok(Self {
            kind,
            page_index,
            encoded,
            locator,
            fingerprint,
        })
    }

    pub fn from_slices(
        kind: PageKind,
        page_index: i32,
        encoded: &[u8],
        locator: &[u8],
        fingerprint: &[u8],
    ) -> Result<Self, PageError> {
        Self::new(
            kind,
            page_index,
            copy_fixed(encoded, "encoded handle")?,
            copy_fixed(locator, "locator token")?,
            copy_fixed(fingerprint, "evaluator fingerprint")?,
        )
    }

    pub fn create(
        kind: PageKind,
        page_index: i32,
        encoded: &[u8],
        locator: &[u8],
        fingerprint: &[u8],
    ) -> Result<Self, PageError> {
        Self::from_slices(kind, page_index, encoded, locator, fingerprint)
    }

    pub const fn kind(&self) -> PageKind {
        self.kind
    }

    pub const fn resource_kind(&self) -> PageKind {
        self.kind
    }

    pub const fn page_index(&self) -> i32 {
        self.page_index
    }

    pub const fn encoded(&self) -> [u8; ENCODED_HANDLE_SIZE] {
        self.encoded
    }

    pub const fn locator_token(&self) -> [u8; LOCATOR_TOKEN_SIZE] {
        self.locator
    }

    pub const fn evaluator_fingerprint(&self) -> Digest {
        self.fingerprint
    }

    pub const fn evaluator_plan_fingerprint(&self) -> Digest {
        self.fingerprint
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.page_index == other.page_index
            && constant_time_eq(&self.encoded, &other.encoded)
            && constant_time_eq(&self.locator, &other.locator)
            && constant_time_eq(&self.fingerprint, &other.fingerprint)
    }
}

impl Clone for PageHandle {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            page_index: self.page_index,
            encoded: self.encoded,
            locator: self.locator,
            fingerprint: self.fingerprint,
        }
    }
}

impl fmt::Debug for PageHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageHandle")
            .field("kind", &self.kind)
            .field("page_index", &self.page_index)
            .field("encoded_length", &ENCODED_HANDLE_SIZE)
            .field("locator_length", &LOCATOR_TOKEN_SIZE)
            .field("fingerprint_length", &FINGERPRINT_SIZE)
            .finish()
    }
}

impl Drop for PageHandle {
    fn drop(&mut self) {
        self.encoded.fill(0);
        self.locator.fill(0);
        self.fingerprint.fill(0);
    }
}

pub type AkenHandle = PageHandle;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PageKey {
    bytes: Vec<u8>,
}

impl PageKey {
    pub fn new(
        kind: PageKind,
        page_index: i32,
        encoded_handle: &[u8],
        locator: &[u8],
    ) -> Result<Self, PageError> {
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        if encoded_handle.len() != ENCODED_HANDLE_SIZE {
            return Err(PageError::InvalidHandleLength {
                field: "encoded handle",
                actual: encoded_handle.len(),
            });
        }
        if locator.len() != LOCATOR_TOKEN_SIZE {
            return Err(PageError::InvalidHandleLength {
                field: "locator token",
                actual: locator.len(),
            });
        }
        let mut bytes = Vec::with_capacity(1 + 4 + ENCODED_HANDLE_SIZE + LOCATOR_TOKEN_SIZE);
        bytes.push(kind.id());
        bytes.extend_from_slice(&page_index.to_be_bytes());
        bytes.extend_from_slice(encoded_handle);
        bytes.extend_from_slice(locator);
        Ok(Self { bytes })
    }

    pub fn from_handle(handle: &PageHandle) -> Self {
        Self::new(
            handle.kind(),
            handle.page_index(),
            &handle.encoded(),
            &handle.locator_token(),
        )
        .expect("validated page handle produces a page key")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PageError> {
        if bytes.is_empty() {
            return Err(PageError::InvalidInput("page key must not be empty"));
        }
        if bytes.len() > MAX_PAGE_KEY_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "page key",
                length: bytes.len(),
                maximum: MAX_PAGE_KEY_SIZE,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn explicit(bytes: &[u8]) -> Result<Self, PageError> {
        Self::from_bytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn kind(&self) -> Option<PageKind> {
        if self.bytes.len() == 1 + 4 + ENCODED_HANDLE_SIZE + LOCATOR_TOKEN_SIZE {
            PageKind::from_id(self.bytes[0]).ok()
        } else {
            None
        }
    }

    pub fn page_index(&self) -> Option<i32> {
        if self.bytes.len() == 1 + 4 + ENCODED_HANDLE_SIZE + LOCATOR_TOKEN_SIZE {
            Some(i32::from_be_bytes([
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
                self.bytes[4],
            ]))
        } else {
            None
        }
    }
}

impl Drop for PageKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Sorted page directory. Lookup is always a binary search over canonical keys.
pub struct PageDirectory<V> {
    entries: Vec<(PageKey, V)>,
}

impl<V> Default for PageDirectory<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<V> PageDirectory<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries<I>(entries: I) -> Result<Self, PageError>
    where
        I: IntoIterator<Item = (PageKey, V)>,
    {
        let mut directory = Self::new();
        for (key, value) in entries {
            directory.insert(key, value)?;
        }
        Ok(directory)
    }

    pub fn insert(&mut self, key: PageKey, value: V) -> Result<(), PageError> {
        match self
            .entries
            .binary_search_by(|(candidate, _)| candidate.cmp(&key))
        {
            Ok(_) => Err(PageError::DuplicatePageKey),
            Err(index) => {
                self.entries.insert(index, (key, value));
                Ok(())
            }
        }
    }

    pub fn lookup(&self, key: &PageKey) -> Option<&V> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
            .map(|index| &self.entries[index].1)
    }

    pub fn get(&self, key: &PageKey) -> Result<&V, PageError> {
        self.lookup(key).ok_or(PageError::NotFound)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &PageKey> {
        self.entries.iter().map(|(key, _)| key)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, value)| value)
    }

    pub fn entries(&self) -> &[(PageKey, V)] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<(PageKey, V)> {
        self.entries
    }
}

pub type SortedPageDirectory<V> = PageDirectory<V>;

#[derive(Eq, PartialEq)]
pub struct PageLayout {
    family: String,
    prefix_length: usize,
    suffix_length: usize,
    header_after_body: bool,
    marker: [u8; 8],
}

impl PageLayout {
    pub fn new(
        family: &str,
        prefix_length: usize,
        suffix_length: usize,
        header_after_body: bool,
        marker: &[u8],
    ) -> Result<Self, PageError> {
        let family = normalize_layout_family(family)?;
        if !(12..=60).contains(&prefix_length) {
            return Err(PageError::InvalidVariant("layout prefix length"));
        }
        if !(8..=40).contains(&suffix_length) {
            return Err(PageError::InvalidVariant("layout suffix length"));
        }
        let marker = copy_fixed(marker, "layout routing marker")?;
        Ok(Self {
            family,
            prefix_length,
            suffix_length,
            header_after_body,
            marker,
        })
    }

    pub fn from_variant(variant: &str) -> Result<Self, PageError> {
        if variant.as_bytes().len() > MAX_VARIANT_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "layout variant",
                length: variant.as_bytes().len(),
                maximum: MAX_VARIANT_SIZE,
            });
        }
        let parts: Vec<&str> = variant.split(':').collect();
        if parts.len() != 6 || parts[0] != "aken4-frame1" {
            return Err(PageError::InvalidVariant("layout"));
        }
        let prefix_length = parts[2]
            .parse::<usize>()
            .map_err(|_| PageError::InvalidVariant("layout prefix length"))?;
        let suffix_length = parts[3]
            .parse::<usize>()
            .map_err(|_| PageError::InvalidVariant("layout suffix length"))?;
        let header_after_body = match parts[4] {
            "head" => false,
            "tail" => true,
            _ => return Err(PageError::InvalidVariant("layout position")),
        };
        let marker = base64_url_decode(parts[5])?;
        let result = Self::new(
            parts[1],
            prefix_length,
            suffix_length,
            header_after_body,
            &marker,
        );
        let mut marker = marker;
        marker.fill(0);
        result
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub const fn prefix_length(&self) -> usize {
        self.prefix_length
    }

    pub const fn suffix_length(&self) -> usize {
        self.suffix_length
    }

    pub const fn header_after_body(&self) -> bool {
        self.header_after_body
    }

    pub fn routing_marker(&self) -> [u8; 8] {
        self.marker
    }

    pub fn variant(&self) -> String {
        let position = if self.header_after_body {
            "tail"
        } else {
            "head"
        };
        format!(
            "aken4-frame1:{}:{}:{}:{}:{}",
            self.family,
            self.prefix_length,
            self.suffix_length,
            position,
            base64_url_encode(&self.marker),
        )
    }

    pub fn minimum_encoded_length(&self) -> usize {
        self.prefix_length + LOGICAL_HEADER_SIZE + GCM_TAG_SIZE + self.suffix_length
    }

    pub fn header_offset(&self, total_length: usize) -> Result<usize, PageError> {
        if total_length < self.minimum_encoded_length() {
            return Err(PageError::Truncated {
                offset: total_length,
                requested: self.minimum_encoded_length(),
                remaining: 0,
            });
        }
        if self.header_after_body {
            total_length
                .checked_sub(self.suffix_length + LOGICAL_HEADER_SIZE)
                .ok_or(PageError::InvalidInput("layout header offset"))
        } else {
            Ok(self.prefix_length)
        }
    }

    pub fn body_offset(&self) -> usize {
        if self.header_after_body {
            self.prefix_length
        } else {
            self.prefix_length + LOGICAL_HEADER_SIZE
        }
    }

    pub fn encoded_length(&self, ciphertext_with_tag_length: usize) -> Result<usize, PageError> {
        if ciphertext_with_tag_length < GCM_TAG_SIZE {
            return Err(PageError::InvalidCiphertextLength);
        }
        self.prefix_length
            .checked_add(LOGICAL_HEADER_SIZE)
            .and_then(|value| value.checked_add(ciphertext_with_tag_length))
            .and_then(|value| value.checked_add(self.suffix_length))
            .ok_or(PageError::LengthTooLarge {
                field: "encoded page",
                length: usize::MAX,
                maximum: MAX_PAGE_FRAME_SIZE,
            })
    }
}

impl Clone for PageLayout {
    fn clone(&self) -> Self {
        Self {
            family: self.family.clone(),
            prefix_length: self.prefix_length,
            suffix_length: self.suffix_length,
            header_after_body: self.header_after_body,
            marker: self.marker,
        }
    }
}

impl Default for PageLayout {
    fn default() -> Self {
        Self::new("default", 12, 8, false, &[0; 8]).expect("default layout is valid")
    }
}

impl fmt::Debug for PageLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageLayout")
            .field("variant", &self.variant())
            .field("prefix_length", &self.prefix_length)
            .field("suffix_length", &self.suffix_length)
            .field("header_after_body", &self.header_after_body)
            .finish()
    }
}

impl Drop for PageLayout {
    fn drop(&mut self) {
        self.marker.fill(0);
    }
}

pub type AkenPageLayout = PageLayout;

fn normalize_layout_family(value: &str) -> Result<String, PageError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 32
        || !normalized.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(PageError::InvalidVariant("layout family"));
    }
    Ok(normalized)
}

fn base64_url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let value = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(TABLE[((value >> 6) & 63) as usize] as char);
        output.push(TABLE[(value & 63) as usize] as char);
        index += 3;
    }
    let remaining = bytes.len() - index;
    if remaining == 1 {
        let value = u32::from(bytes[index]) << 16;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
    } else if remaining == 2 {
        let value = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(TABLE[((value >> 6) & 63) as usize] as char);
    }
    output
}

fn base64_url_decode(value: &str) -> Result<Vec<u8>, PageError> {
    if value.as_bytes().len() > MAX_VARIANT_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "layout marker",
            length: value.as_bytes().len(),
            maximum: MAX_VARIANT_SIZE,
        });
    }
    if value.is_empty()
        || value.len() % 4 == 1
        || value.bytes().any(|byte| {
            !matches!(byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'
            )
        })
    {
        return Err(PageError::InvalidVariant("layout marker"));
    }
    let mut values = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        values.push(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(PageError::InvalidVariant("layout marker")),
        });
    }
    let capacity =
        value
            .len()
            .checked_mul(3)
            .map(|length| length / 4)
            .ok_or(PageError::LengthTooLarge {
                field: "layout marker",
                length: value.len(),
                maximum: MAX_VARIANT_SIZE,
            })?;
    let mut output = Vec::with_capacity(capacity);
    let mut index = 0;
    while index + 4 <= values.len() {
        let bits = (u32::from(values[index]) << 18)
            | (u32::from(values[index + 1]) << 12)
            | (u32::from(values[index + 2]) << 6)
            | u32::from(values[index + 3]);
        output.push((bits >> 16) as u8);
        output.push((bits >> 8) as u8);
        output.push(bits as u8);
        index += 4;
    }
    match values.len() - index {
        0 => {}
        2 => {
            let bits = (u32::from(values[index]) << 18) | (u32::from(values[index + 1]) << 12);
            if values[index + 1] & 0x0f != 0 {
                return Err(PageError::InvalidVariant("layout marker padding"));
            }
            output.push((bits >> 16) as u8);
        }
        3 => {
            let bits = (u32::from(values[index]) << 18)
                | (u32::from(values[index + 1]) << 12)
                | (u32::from(values[index + 2]) << 6);
            if values[index + 2] & 0x03 != 0 {
                return Err(PageError::InvalidVariant("layout marker padding"));
            }
            output.push((bits >> 16) as u8);
            output.push((bits >> 8) as u8);
        }
        _ => return Err(PageError::InvalidVariant("layout marker")),
    }
    if output.len() != 8 {
        return Err(PageError::InvalidLength {
            field: "layout routing marker",
            expected: 8,
            actual: output.len(),
        });
    }
    Ok(output)
}

pub struct PageHeader {
    kind: PageKind,
    page_index: i32,
    plaintext_length: i32,
    nonce: [u8; NONCE_SIZE],
    commitment: Digest,
    identity_hash: Digest,
    evaluator_fingerprint: Digest,
    codec_hash: Digest,
    layout_hash: Digest,
    locator: [u8; LOCATOR_TOKEN_SIZE],
    ciphertext_length: i32,
}

impl PageHeader {
    pub fn new(
        kind: PageKind,
        page_index: i32,
        plaintext_length: usize,
        nonce: [u8; NONCE_SIZE],
        commitment: &[u8],
        identity: &[u8],
        evaluator_fingerprint: &[u8],
        codec_bytes: &[u8],
        layout_bytes: &[u8],
        locator: &[u8],
    ) -> Result<Self, PageError> {
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        if plaintext_length > MAX_PAGE_PLAINTEXT_SIZE
            || plaintext_length > i32::MAX as usize - GCM_TAG_SIZE
        {
            return Err(PageError::LengthTooLarge {
                field: "plaintext",
                length: plaintext_length,
                maximum: (i32::MAX as usize).saturating_sub(GCM_TAG_SIZE),
            });
        }
        if identity.is_empty() || identity.len() > MAX_LOGICAL_IDENTITY_SIZE {
            return Err(PageError::InvalidInput(
                "logical identity length is invalid",
            ));
        }
        if codec_bytes.is_empty() || codec_bytes.len() > MAX_VARIANT_SIZE {
            return Err(PageError::InvalidVariant("codec"));
        }
        if layout_bytes.is_empty() || layout_bytes.len() > MAX_VARIANT_SIZE * 1024 {
            return Err(PageError::InvalidVariant("layout"));
        }
        Ok(Self {
            kind,
            page_index,
            plaintext_length: plaintext_length as i32,
            nonce,
            commitment: copy_fixed(commitment, "artifact commitment")?,
            identity_hash: sha256(identity),
            evaluator_fingerprint: copy_fixed(evaluator_fingerprint, "evaluator fingerprint")?,
            codec_hash: sha256(codec_bytes),
            layout_hash: sha256(layout_bytes),
            locator: copy_fixed(locator, "locator token")?,
            ciphertext_length: (plaintext_length + GCM_TAG_SIZE) as i32,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PageError> {
        if bytes.len() != LOGICAL_HEADER_SIZE {
            return Err(PageError::InvalidLength {
                field: "logical page header",
                expected: LOGICAL_HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        let kind = PageKind::from_id(bytes[OFFSET_KIND])?;
        let page_index = read_i32_at(bytes, OFFSET_PAGE_INDEX)?;
        let plaintext_length = read_i32_at(bytes, OFFSET_PLAINTEXT_LENGTH)?;
        let ciphertext_length = read_i32_at(bytes, OFFSET_CIPHERTEXT_LENGTH)?;
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        if plaintext_length < 0 || ciphertext_length < 0 {
            return Err(PageError::InvalidCiphertextLength);
        }
        let expected_ciphertext_length = plaintext_length
            .checked_add(GCM_TAG_SIZE as i32)
            .ok_or(PageError::InvalidCiphertextLength)?;
        if ciphertext_length != expected_ciphertext_length {
            return Err(PageError::InvalidCiphertextLength);
        }
        Ok(Self {
            kind,
            page_index,
            plaintext_length,
            nonce: copy_fixed(&bytes[OFFSET_NONCE..OFFSET_NONCE + NONCE_SIZE], "nonce")?,
            commitment: copy_fixed(
                &bytes[OFFSET_COMMITMENT..OFFSET_COMMITMENT + DIGEST_SIZE],
                "artifact commitment",
            )?,
            identity_hash: copy_fixed(
                &bytes[OFFSET_IDENTITY_HASH..OFFSET_IDENTITY_HASH + DIGEST_SIZE],
                "identity hash",
            )?,
            evaluator_fingerprint: copy_fixed(
                &bytes[OFFSET_EVALUATOR_FINGERPRINT..OFFSET_EVALUATOR_FINGERPRINT + DIGEST_SIZE],
                "evaluator fingerprint",
            )?,
            codec_hash: copy_fixed(
                &bytes[OFFSET_CODEC_HASH..OFFSET_CODEC_HASH + DIGEST_SIZE],
                "codec hash",
            )?,
            layout_hash: copy_fixed(
                &bytes[OFFSET_LAYOUT_HASH..OFFSET_LAYOUT_HASH + DIGEST_SIZE],
                "layout hash",
            )?,
            locator: copy_fixed(
                &bytes[OFFSET_LOCATOR..OFFSET_LOCATOR + LOCATOR_TOKEN_SIZE],
                "locator token",
            )?,
            ciphertext_length,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; LOGICAL_HEADER_SIZE];
        bytes[OFFSET_KIND] = self.kind.id();
        bytes[OFFSET_PAGE_INDEX..OFFSET_PAGE_INDEX + 4]
            .copy_from_slice(&self.page_index.to_be_bytes());
        bytes[OFFSET_PLAINTEXT_LENGTH..OFFSET_PLAINTEXT_LENGTH + 4]
            .copy_from_slice(&self.plaintext_length.to_be_bytes());
        bytes[OFFSET_NONCE..OFFSET_NONCE + NONCE_SIZE].copy_from_slice(&self.nonce);
        bytes[OFFSET_COMMITMENT..OFFSET_COMMITMENT + DIGEST_SIZE].copy_from_slice(&self.commitment);
        bytes[OFFSET_IDENTITY_HASH..OFFSET_IDENTITY_HASH + DIGEST_SIZE]
            .copy_from_slice(&self.identity_hash);
        bytes[OFFSET_EVALUATOR_FINGERPRINT..OFFSET_EVALUATOR_FINGERPRINT + DIGEST_SIZE]
            .copy_from_slice(&self.evaluator_fingerprint);
        bytes[OFFSET_CODEC_HASH..OFFSET_CODEC_HASH + DIGEST_SIZE].copy_from_slice(&self.codec_hash);
        bytes[OFFSET_LAYOUT_HASH..OFFSET_LAYOUT_HASH + DIGEST_SIZE]
            .copy_from_slice(&self.layout_hash);
        bytes[OFFSET_LOCATOR..OFFSET_LOCATOR + LOCATOR_TOKEN_SIZE].copy_from_slice(&self.locator);
        bytes[OFFSET_CIPHERTEXT_LENGTH..OFFSET_CIPHERTEXT_LENGTH + 4]
            .copy_from_slice(&self.ciphertext_length.to_be_bytes());
        bytes
    }

    pub const fn kind(&self) -> PageKind {
        self.kind
    }

    pub const fn page_index(&self) -> i32 {
        self.page_index
    }

    pub const fn plaintext_length(&self) -> usize {
        self.plaintext_length as usize
    }

    pub const fn ciphertext_length(&self) -> usize {
        self.ciphertext_length as usize
    }

    pub const fn nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce
    }

    pub const fn commitment(&self) -> Digest {
        self.commitment
    }

    pub const fn identity_hash(&self) -> Digest {
        self.identity_hash
    }

    pub const fn evaluator_fingerprint(&self) -> Digest {
        self.evaluator_fingerprint
    }

    pub const fn codec_hash(&self) -> Digest {
        self.codec_hash
    }

    pub const fn layout_hash(&self) -> Digest {
        self.layout_hash
    }

    pub const fn locator(&self) -> [u8; LOCATOR_TOKEN_SIZE] {
        self.locator
    }

    pub fn validate_binding(
        &self,
        commitment: &[u8],
        identity: &[u8],
        page_index: i32,
        kind: PageKind,
        evaluator_fingerprint: &[u8],
        codec_bytes: &[u8],
        layout_bytes: &[u8],
        locator: &[u8],
        actual_ciphertext_length: Option<usize>,
    ) -> Result<(), PageError> {
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        let commitment: Digest = copy_fixed(commitment, "artifact commitment")?;
        let fingerprint: Digest = copy_fixed(evaluator_fingerprint, "evaluator fingerprint")?;
        let locator: [u8; LOCATOR_TOKEN_SIZE] = copy_fixed(locator, "locator token")?;
        if self.kind != kind || self.page_index != page_index {
            return Err(PageError::BindingMismatch("page header identity"));
        }
        if !constant_time_eq(&self.commitment, &commitment) {
            return Err(PageError::HashMismatch("artifact commitment"));
        }
        if !constant_time_eq(&self.identity_hash, &sha256(identity)) {
            return Err(PageError::HashMismatch("logical identity"));
        }
        if !constant_time_eq(&self.evaluator_fingerprint, &fingerprint) {
            return Err(PageError::BindingMismatch("evaluator fingerprint"));
        }
        if !constant_time_eq(&self.codec_hash, &sha256(codec_bytes)) {
            return Err(PageError::HashMismatch("codec"));
        }
        if !constant_time_eq(&self.layout_hash, &sha256(layout_bytes)) {
            return Err(PageError::HashMismatch("layout"));
        }
        if !constant_time_eq(&self.locator, &locator) {
            return Err(PageError::BindingMismatch("locator"));
        }
        if let Some(actual) = actual_ciphertext_length {
            if actual != self.ciphertext_length() {
                return Err(PageError::InvalidCiphertextLength);
            }
        }
        Ok(())
    }

    pub fn validate_page_binding(
        &self,
        commitment: &[u8],
        identity: &[u8],
        page_index: i32,
        kind: PageKind,
        evaluator_fingerprint: &[u8],
        codec_bytes: &[u8],
        layout_bytes: &[u8],
        locator: &[u8],
    ) -> Result<(), PageError> {
        self.validate_binding(
            commitment,
            identity,
            page_index,
            kind,
            evaluator_fingerprint,
            codec_bytes,
            layout_bytes,
            locator,
            None,
        )
    }

    pub fn binding_digest(&self) -> Digest {
        let encoded = self.encode();
        let digest = hash_domain_framed(HEADER_BINDING_DOMAIN, &[&encoded]);
        let mut encoded = encoded;
        encoded.fill(0);
        digest
    }
}

impl Clone for PageHeader {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            page_index: self.page_index,
            plaintext_length: self.plaintext_length,
            nonce: self.nonce,
            commitment: self.commitment,
            identity_hash: self.identity_hash,
            evaluator_fingerprint: self.evaluator_fingerprint,
            codec_hash: self.codec_hash,
            layout_hash: self.layout_hash,
            locator: self.locator,
            ciphertext_length: self.ciphertext_length,
        }
    }
}

impl fmt::Debug for PageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageHeader")
            .field("kind", &self.kind)
            .field("page_index", &self.page_index)
            .field("plaintext_length", &self.plaintext_length)
            .field("ciphertext_length", &self.ciphertext_length)
            .finish()
    }
}

impl Drop for PageHeader {
    fn drop(&mut self) {
        self.nonce.fill(0);
        self.commitment.fill(0);
        self.identity_hash.fill(0);
        self.evaluator_fingerprint.fill(0);
        self.codec_hash.fill(0);
        self.layout_hash.fill(0);
        self.locator.fill(0);
    }
}

pub type AkenResourceHeader = PageHeader;
pub type LogicalPageHeader = PageHeader;

fn read_i32_at(bytes: &[u8], offset: usize) -> Result<i32, PageError> {
    let end = offset
        .checked_add(4)
        .ok_or(PageError::InvalidInput("header offset"))?;
    if end > bytes.len() {
        return Err(PageError::Truncated {
            offset,
            requested: 4,
            remaining: bytes.len().saturating_sub(offset),
        });
    }
    Ok(i32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

/// Constructs the exact current Kotlin page AAD.
pub fn build_aad(
    commitment: &[u8],
    identity: &[u8],
    page_index: i32,
    kind: PageKind,
    fingerprint: &[u8],
    codec_bytes: &[u8],
    layout_bytes: &[u8],
    locator: &[u8],
    header: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, PageError> {
    if page_index < 0 {
        return Err(PageError::InvalidPageIndex(page_index));
    }
    copy_fixed::<DIGEST_SIZE>(commitment, "artifact commitment")?;
    copy_fixed::<DIGEST_SIZE>(fingerprint, "evaluator fingerprint")?;
    copy_fixed::<LOCATOR_TOKEN_SIZE>(locator, "locator token")?;
    if identity.is_empty() || identity.len() > MAX_LOGICAL_IDENTITY_SIZE {
        return Err(PageError::InvalidInput(
            "logical identity length is invalid",
        ));
    }
    if codec_bytes.is_empty() || codec_bytes.len() > MAX_VARIANT_SIZE {
        return Err(PageError::InvalidVariant("codec"));
    }
    if layout_bytes.is_empty() || layout_bytes.len() > MAX_VARIANT_SIZE * 1024 {
        return Err(PageError::InvalidVariant("layout"));
    }
    if header.len() != LOGICAL_HEADER_SIZE {
        return Err(PageError::InvalidLength {
            field: "logical page header",
            expected: LOGICAL_HEADER_SIZE,
            actual: header.len(),
        });
    }
    let framed_size = |length: usize| length.checked_add(4);
    let total = PAGE_AAD_DOMAIN
        .len()
        .checked_add(DIGEST_SIZE)
        .and_then(|value| framed_size(identity.len()).and_then(|size| value.checked_add(size)))
        .and_then(|value| value.checked_add(4 + 1 + DIGEST_SIZE))
        .and_then(|value| framed_size(codec_bytes.len()).and_then(|size| value.checked_add(size)))
        .and_then(|value| framed_size(layout_bytes.len()).and_then(|size| value.checked_add(size)))
        .and_then(|value| value.checked_add(LOCATOR_TOKEN_SIZE))
        .and_then(|value| framed_size(header.len()).and_then(|size| value.checked_add(size)))
        .and_then(|value| framed_size(prefix.len()).and_then(|size| value.checked_add(size)))
        .and_then(|value| framed_size(suffix.len()).and_then(|size| value.checked_add(size)))
        .ok_or(PageError::LengthTooLarge {
            field: "page AAD",
            length: usize::MAX,
            maximum: MAX_AAD_SIZE,
        })?;
    if total > MAX_AAD_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "page AAD",
            length: total,
            maximum: MAX_AAD_SIZE,
        });
    }
    let mut writer = Writer::new(total);
    writer.write(PAGE_AAD_DOMAIN)?;
    writer.write(commitment)?;
    writer.write_frame(identity, "logical identity")?;
    writer.write_i32(page_index)?;
    writer.write_u8(kind.id())?;
    writer.write(fingerprint)?;
    writer.write_frame(codec_bytes, "codec")?;
    writer.write_frame(layout_bytes, "layout")?;
    writer.write(locator)?;
    writer.write_frame(header, "logical page header")?;
    writer.write_frame(prefix, "page prefix")?;
    writer.write_frame(suffix, "page suffix")?;
    Ok(writer.finish())
}

pub fn build_page_aad(
    commitment: &[u8],
    identity: &[u8],
    page_index: i32,
    kind: PageKind,
    fingerprint: &[u8],
    codec_bytes: &[u8],
    layout_bytes: &[u8],
    locator: &[u8],
    header: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, PageError> {
    build_aad(
        commitment,
        identity,
        page_index,
        kind,
        fingerprint,
        codec_bytes,
        layout_bytes,
        locator,
        header,
        prefix,
        suffix,
    )
}

pub fn normalize_codec_variant(variant: &str) -> Result<String, PageError> {
    match variant.trim().to_ascii_lowercase().as_str() {
        "gcm" | "aes-256-gcm" => Ok(CANONICAL_CODEC_VARIANT.to_owned()),
        _ => Err(PageError::InvalidVariant("codec")),
    }
}

pub struct AkenResourceCodec;

impl AkenResourceCodec {
    pub const LOGICAL_HEADER_SIZE: usize = LOGICAL_HEADER_SIZE;
    pub const GCM_TAG_SIZE: usize = GCM_TAG_SIZE;
    pub const NONCE_SIZE: usize = NONCE_SIZE;
    pub const OFFSET_KIND: usize = OFFSET_KIND;
    pub const OFFSET_PAGE_INDEX: usize = OFFSET_PAGE_INDEX;
    pub const OFFSET_PLAINTEXT_LENGTH: usize = OFFSET_PLAINTEXT_LENGTH;
    pub const OFFSET_NONCE: usize = OFFSET_NONCE;
    pub const OFFSET_COMMITMENT: usize = OFFSET_COMMITMENT;
    pub const OFFSET_IDENTITY_HASH: usize = OFFSET_IDENTITY_HASH;
    pub const OFFSET_EVALUATOR_FINGERPRINT: usize = OFFSET_EVALUATOR_FINGERPRINT;
    pub const OFFSET_CODEC_HASH: usize = OFFSET_CODEC_HASH;
    pub const OFFSET_LAYOUT_HASH: usize = OFFSET_LAYOUT_HASH;
    pub const OFFSET_LOCATOR: usize = OFFSET_LOCATOR;
    pub const OFFSET_CIPHERTEXT_LENGTH: usize = OFFSET_CIPHERTEXT_LENGTH;
    pub const CANONICAL_CODEC_VARIANT: &'static str = CANONICAL_CODEC_VARIANT;

    pub fn normalize_codec_variant(variant: &str) -> Result<String, PageError> {
        normalize_codec_variant(variant)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_aad(
        commitment: &[u8],
        identity: &[u8],
        page_index: i32,
        kind: PageKind,
        fingerprint: &[u8],
        codec_bytes: &[u8],
        layout_bytes: &[u8],
        locator: &[u8],
        header: &[u8],
        prefix: &[u8],
        suffix: &[u8],
    ) -> Result<Vec<u8>, PageError> {
        build_aad(
            commitment,
            identity,
            page_index,
            kind,
            fingerprint,
            codec_bytes,
            layout_bytes,
            locator,
            header,
            prefix,
            suffix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        plain: &[u8],
        dek: &[u8],
        commitment: &[u8],
        identity: &[u8],
        page_index: i32,
        kind: PageKind,
        fingerprint: &[u8],
        codec: &str,
        layout: &PageLayout,
        locator: &[u8],
        nonce: &[u8],
        prefix: &[u8],
        suffix: &[u8],
    ) -> Result<Vec<u8>, PageError> {
        encode_page(
            plain,
            dek,
            commitment,
            identity,
            page_index,
            kind,
            fingerprint,
            codec,
            layout,
            locator,
            nonce,
            prefix,
            suffix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        encoded: &[u8],
        dek: &[u8],
        commitment: &[u8],
        identity: &[u8],
        page_index: i32,
        kind: PageKind,
        fingerprint: &[u8],
        codec: &str,
        layout: &PageLayout,
        locator: &[u8],
    ) -> Result<Vec<u8>, PageError> {
        decode_page(
            encoded,
            dek,
            commitment,
            identity,
            page_index,
            kind,
            fingerprint,
            codec,
            layout,
            locator,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn encode_page(
    plain: &[u8],
    dek: &[u8],
    commitment: &[u8],
    identity: &[u8],
    page_index: i32,
    kind: PageKind,
    fingerprint: &[u8],
    codec: &str,
    layout: &PageLayout,
    locator: &[u8],
    nonce: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, PageError> {
    if plain.len() > MAX_PAGE_PLAINTEXT_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "page plaintext",
            length: plain.len(),
            maximum: MAX_PAGE_PLAINTEXT_SIZE,
        });
    }
    let canonical_codec = normalize_codec_variant(codec)?;
    let codec_bytes = canonical_codec.as_bytes();
    let layout_variant = layout.variant();
    let layout_bytes = layout_variant.as_bytes();
    let nonce = copy_fixed::<NONCE_SIZE>(nonce, "GCM nonce")?;
    if prefix.len() != layout.prefix_length() {
        return Err(PageError::InvalidLength {
            field: "page prefix",
            expected: layout.prefix_length(),
            actual: prefix.len(),
        });
    }
    if suffix.len() != layout.suffix_length() {
        return Err(PageError::InvalidLength {
            field: "page suffix",
            expected: layout.suffix_length(),
            actual: suffix.len(),
        });
    }
    let header = PageHeader::new(
        kind,
        page_index,
        plain.len(),
        nonce,
        commitment,
        identity,
        fingerprint,
        codec_bytes,
        layout_bytes,
        locator,
    )?;
    let header_bytes = header.encode();
    let mut aad = build_aad(
        commitment,
        identity,
        page_index,
        kind,
        fingerprint,
        codec_bytes,
        layout_bytes,
        locator,
        &header_bytes,
        prefix,
        suffix,
    )?;
    let mut body = gcm_encrypt(dek, &nonce, &aad, plain)?;
    let encoded_length = layout.encoded_length(body.len())?;
    if encoded_length > MAX_PAGE_FRAME_SIZE {
        aad.fill(0);
        body.fill(0);
        return Err(PageError::LengthTooLarge {
            field: "encoded page",
            length: encoded_length,
            maximum: MAX_PAGE_FRAME_SIZE,
        });
    }
    let mut encoded = Vec::with_capacity(encoded_length);
    encoded.extend_from_slice(prefix);
    if layout.header_after_body() {
        encoded.extend_from_slice(&body);
        encoded.extend_from_slice(&header_bytes);
    } else {
        encoded.extend_from_slice(&header_bytes);
        encoded.extend_from_slice(&body);
    }
    encoded.extend_from_slice(suffix);
    aad.fill(0);
    body.fill(0);
    if encoded.len() != encoded_length {
        encoded.fill(0);
        return Err(PageError::InvalidInput("encoded page length mismatch"));
    }
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
pub fn decode_page(
    encoded: &[u8],
    dek: &[u8],
    commitment: &[u8],
    identity: &[u8],
    page_index: i32,
    kind: PageKind,
    fingerprint: &[u8],
    codec: &str,
    layout: &PageLayout,
    locator: &[u8],
) -> Result<Vec<u8>, PageError> {
    if encoded.len() > MAX_PAGE_FRAME_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "encoded page",
            length: encoded.len(),
            maximum: MAX_PAGE_FRAME_SIZE,
        });
    }
    let canonical_codec = normalize_codec_variant(codec)?;
    let codec_bytes = canonical_codec.as_bytes();
    let layout_variant = layout.variant();
    let layout_bytes = layout_variant.as_bytes();
    let expected_header_offset = layout.header_offset(encoded.len())?;
    if expected_header_offset + LOGICAL_HEADER_SIZE > encoded.len() {
        return Err(PageError::Truncated {
            offset: expected_header_offset,
            requested: LOGICAL_HEADER_SIZE,
            remaining: encoded.len().saturating_sub(expected_header_offset),
        });
    }
    let header_bytes =
        &encoded[expected_header_offset..expected_header_offset + LOGICAL_HEADER_SIZE];
    let header = PageHeader::decode(header_bytes)?;
    let body_offset = layout.body_offset();
    let body_end = body_offset
        .checked_add(header.ciphertext_length())
        .ok_or(PageError::InvalidCiphertextLength)?;
    let suffix_offset = encoded
        .len()
        .checked_sub(layout.suffix_length())
        .ok_or(PageError::InvalidInput("page suffix offset"))?;
    if body_offset > body_end || body_end > encoded.len() || suffix_offset < body_end {
        return Err(PageError::InvalidCiphertextLength);
    }
    let expected_length = layout.encoded_length(header.ciphertext_length())?;
    if expected_length != encoded.len() {
        return Err(PageError::InvalidLength {
            field: "encoded page",
            expected: expected_length,
            actual: encoded.len(),
        });
    }
    let expected_header_offset_again = if layout.header_after_body() {
        body_end
    } else {
        layout.prefix_length()
    };
    if expected_header_offset_again != expected_header_offset {
        return Err(PageError::BindingMismatch("page layout/header position"));
    }
    header.validate_binding(
        commitment,
        identity,
        page_index,
        kind,
        fingerprint,
        codec_bytes,
        layout_bytes,
        locator,
        Some(header.ciphertext_length()),
    )?;
    let prefix = &encoded[..layout.prefix_length()];
    let suffix = &encoded[suffix_offset..];
    let mut aad = build_aad(
        commitment,
        identity,
        page_index,
        kind,
        fingerprint,
        codec_bytes,
        layout_bytes,
        locator,
        header_bytes,
        prefix,
        suffix,
    )?;
    let result = gcm_decrypt(dek, &header.nonce, &aad, &encoded[body_offset..body_end]);
    aad.fill(0);
    result.and_then(|plain| {
        if plain.len() != header.plaintext_length() {
            let mut plain = plain;
            plain.fill(0);
            Err(PageError::InvalidCiphertextLength)
        } else {
            Ok(plain)
        }
    })
}

pub fn decode_page_or_none(
    encoded: &[u8],
    dek: &[u8],
    commitment: &[u8],
    identity: &[u8],
    page_index: i32,
    kind: PageKind,
    fingerprint: &[u8],
    codec: &str,
    layout: &PageLayout,
    locator: &[u8],
) -> Option<Vec<u8>> {
    decode_page(
        encoded,
        dek,
        commitment,
        identity,
        page_index,
        kind,
        fingerprint,
        codec,
        layout,
        locator,
    )
    .ok()
}

#[derive(Eq, PartialEq)]
pub struct LeafIdentity {
    kind: PageKind,
    page_index: i32,
    handle_encoding: [u8; ENCODED_HANDLE_SIZE],
    locator_token: [u8; LOCATOR_TOKEN_SIZE],
    evaluator_fingerprint: Digest,
    logical_identity: Vec<u8>,
}

impl LeafIdentity {
    pub fn new(
        kind: PageKind,
        page_index: i32,
        handle_encoding: &[u8],
        locator_token: &[u8],
        evaluator_fingerprint: &[u8],
        logical_identity: &[u8],
    ) -> Result<Self, PageError> {
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        if logical_identity.is_empty() || logical_identity.len() > MAX_LOGICAL_IDENTITY_SIZE {
            return Err(PageError::InvalidInput(
                "logical identity length is invalid",
            ));
        }
        Ok(Self {
            kind,
            page_index,
            handle_encoding: copy_fixed(handle_encoding, "encoded handle")?,
            locator_token: copy_fixed(locator_token, "locator token")?,
            evaluator_fingerprint: copy_fixed(evaluator_fingerprint, "evaluator fingerprint")?,
            logical_identity: logical_identity.to_vec(),
        })
    }

    pub fn from_handle(handle: &PageHandle, logical_identity: &[u8]) -> Result<Self, PageError> {
        Self::new(
            handle.kind(),
            handle.page_index(),
            &handle.encoded(),
            &handle.locator_token(),
            &handle.evaluator_fingerprint(),
            logical_identity,
        )
    }

    pub fn of(
        kind: PageKind,
        page_index: i32,
        handle_encoding: &[u8],
        locator_token: &[u8],
        evaluator_fingerprint: &[u8],
        logical_identity: &[u8],
    ) -> Result<Self, PageError> {
        Self::new(
            kind,
            page_index,
            handle_encoding,
            locator_token,
            evaluator_fingerprint,
            logical_identity,
        )
    }

    pub const fn kind(&self) -> PageKind {
        self.kind
    }

    pub const fn resource_kind(&self) -> PageKind {
        self.kind
    }

    pub const fn page_index(&self) -> i32 {
        self.page_index
    }

    pub const fn handle_encoding(&self) -> [u8; ENCODED_HANDLE_SIZE] {
        self.handle_encoding
    }

    pub const fn locator_token(&self) -> [u8; LOCATOR_TOKEN_SIZE] {
        self.locator_token
    }

    pub const fn evaluator_fingerprint(&self) -> Digest {
        self.evaluator_fingerprint
    }

    pub const fn locator_token_ref(&self) -> &[u8; LOCATOR_TOKEN_SIZE] {
        &self.locator_token
    }

    pub const fn evaluator_fingerprint_ref(&self) -> &Digest {
        &self.evaluator_fingerprint
    }

    pub fn logical_identity(&self) -> &[u8] {
        &self.logical_identity
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new(MAX_LEAF_IDENTITY_ENCODING_SIZE);
        writer
            .write_u8(self.kind.id())
            .expect("validated leaf kind");
        writer
            .write_i32(self.page_index)
            .expect("validated leaf index");
        writer
            .write(&self.handle_encoding)
            .expect("validated leaf handle");
        writer
            .write(&self.locator_token)
            .expect("validated leaf locator");
        writer
            .write(&self.evaluator_fingerprint)
            .expect("validated leaf fingerprint");
        writer
            .write_frame(&self.logical_identity, "logical identity")
            .expect("validated leaf identity");
        writer.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PageError> {
        if encoded.is_empty() || encoded.len() > MAX_LEAF_IDENTITY_ENCODING_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "leaf identity",
                length: encoded.len(),
                maximum: MAX_LEAF_IDENTITY_ENCODING_SIZE,
            });
        }
        let mut cursor = Cursor::new(encoded);
        let kind = PageKind::from_id(cursor.read_u8()?)?;
        let page_index = cursor.read_i32_be()?;
        let handle = cursor.read_fixed(ENCODED_HANDLE_SIZE)?;
        let locator = cursor.read_fixed(LOCATOR_TOKEN_SIZE)?;
        let fingerprint = cursor.read_fixed(FINGERPRINT_SIZE)?;
        let logical_identity =
            cursor.read_frame(MAX_LOGICAL_IDENTITY_SIZE, false, "logical identity")?;
        cursor.require_empty()?;
        Self::new(
            kind,
            page_index,
            &handle,
            &locator,
            &fingerprint,
            &logical_identity,
        )
    }

    pub fn matches_handle(&self, handle: &PageHandle) -> bool {
        self.kind == handle.kind()
            && self.page_index == handle.page_index()
            && constant_time_eq(&self.handle_encoding, &handle.encoded())
            && constant_time_eq(&self.locator_token, &handle.locator_token())
            && constant_time_eq(&self.evaluator_fingerprint, &handle.evaluator_fingerprint())
    }

    pub fn binding_digest(&self) -> Digest {
        let encoded = self.encode();
        let result = hash_domain_framed(HEADER_BINDING_DOMAIN, &[&encoded]);
        let mut encoded = encoded;
        encoded.fill(0);
        result
    }
}

impl Clone for LeafIdentity {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            page_index: self.page_index,
            handle_encoding: self.handle_encoding,
            locator_token: self.locator_token,
            evaluator_fingerprint: self.evaluator_fingerprint,
            logical_identity: self.logical_identity.clone(),
        }
    }
}

impl fmt::Debug for LeafIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeafIdentity")
            .field("kind", &self.kind)
            .field("page_index", &self.page_index)
            .field("logical_identity_length", &self.logical_identity.len())
            .finish()
    }
}

impl Drop for LeafIdentity {
    fn drop(&mut self) {
        self.handle_encoding.fill(0);
        self.locator_token.fill(0);
        self.evaluator_fingerprint.fill(0);
        self.logical_identity.fill(0);
    }
}

pub type AkenHighValueLeafIdentity = LeafIdentity;

#[derive(Eq, PartialEq)]
pub struct PageRoute {
    leaf_identity: LeafIdentity,
    resource_path: String,
    resource_offset: i32,
    stored_length: i32,
    codec_variant: String,
    layout_variant: String,
    logical_binding_path: String,
}

impl PageRoute {
    pub fn new(
        leaf_identity: LeafIdentity,
        resource_path: &str,
        resource_offset: i32,
        stored_length: i32,
        codec_variant: &str,
        layout_variant: &str,
        logical_binding_path: &str,
    ) -> Result<Self, PageError> {
        validate_path(resource_path, "resource path")?;
        validate_path(logical_binding_path, "logical binding path")?;
        validate_variant(codec_variant, "codec")?;
        validate_variant(layout_variant, "layout")?;
        if resource_offset < 0 || stored_length <= 0 {
            return Err(PageError::InvalidInput("route bounds are invalid"));
        }
        if stored_length as usize > MAX_PAGE_FRAME_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "route stored length",
                length: stored_length as usize,
                maximum: MAX_PAGE_FRAME_SIZE,
            });
        }
        Ok(Self {
            leaf_identity,
            resource_path: resource_path.to_owned(),
            resource_offset,
            stored_length,
            codec_variant: codec_variant.to_owned(),
            layout_variant: layout_variant.to_owned(),
            logical_binding_path: logical_binding_path.to_owned(),
        })
    }

    pub fn from_handle(
        handle: &PageHandle,
        logical_identity: &[u8],
        resource_path: &str,
        resource_offset: i32,
        stored_length: i32,
        codec_variant: &str,
        layout_variant: &str,
        logical_binding_path: Option<&str>,
    ) -> Result<Self, PageError> {
        let identity = LeafIdentity::from_handle(handle, logical_identity)?;
        let binding_path = logical_binding_path.unwrap_or(resource_path);
        Self::new(
            identity,
            resource_path,
            resource_offset,
            stored_length,
            codec_variant,
            layout_variant,
            binding_path,
        )
    }

    pub fn leaf_identity(&self) -> &LeafIdentity {
        &self.leaf_identity
    }

    pub const fn resource_kind(&self) -> PageKind {
        self.leaf_identity.kind()
    }

    pub const fn page_index(&self) -> i32 {
        self.leaf_identity.page_index()
    }

    pub fn resource_path(&self) -> &str {
        &self.resource_path
    }

    pub const fn resource_offset(&self) -> i32 {
        self.resource_offset
    }

    pub const fn stored_length(&self) -> i32 {
        self.stored_length
    }

    pub fn codec_variant(&self) -> &str {
        &self.codec_variant
    }

    pub fn layout_variant(&self) -> &str {
        &self.layout_variant
    }

    pub fn logical_binding_path(&self) -> &str {
        &self.logical_binding_path
    }

    pub fn handle_encoding(&self) -> [u8; ENCODED_HANDLE_SIZE] {
        self.leaf_identity.handle_encoding()
    }

    pub fn locator_token(&self) -> [u8; LOCATOR_TOKEN_SIZE] {
        self.leaf_identity.locator_token()
    }

    pub fn evaluator_fingerprint(&self) -> Digest {
        self.leaf_identity.evaluator_fingerprint()
    }

    pub fn matches_handle(&self, handle: &PageHandle) -> bool {
        self.leaf_identity.matches_handle(handle)
    }

    pub fn encode(&self) -> Vec<u8> {
        let identity = self.leaf_identity.encode();
        let mut writer = Writer::new(MAX_ROUTE_ENCODING_SIZE);
        writer
            .write_frame(&identity, "route leaf identity")
            .expect("validated route identity");
        writer
            .write_frame(self.resource_path.as_bytes(), "resource path")
            .expect("validated route path");
        writer
            .write_i32(self.resource_offset)
            .expect("validated route offset");
        writer
            .write_i32(self.stored_length)
            .expect("validated route length");
        writer
            .write_frame(self.codec_variant.as_bytes(), "codec")
            .expect("validated route codec");
        writer
            .write_frame(self.layout_variant.as_bytes(), "layout")
            .expect("validated route layout");
        writer
            .write_frame(self.logical_binding_path.as_bytes(), "logical binding path")
            .expect("validated route binding path");
        let mut identity = identity;
        identity.fill(0);
        writer.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PageError> {
        if encoded.is_empty() || encoded.len() > MAX_ROUTE_ENCODING_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "route",
                length: encoded.len(),
                maximum: MAX_ROUTE_ENCODING_SIZE,
            });
        }
        let mut cursor = Cursor::new(encoded);
        let identity_bytes = cursor.read_frame(
            MAX_LEAF_IDENTITY_ENCODING_SIZE,
            false,
            "route leaf identity",
        )?;
        let identity = LeafIdentity::decode(&identity_bytes)?;
        let path_bytes = cursor.read_frame(MAX_RESOURCE_PATH_SIZE, false, "resource path")?;
        let resource_path = decode_utf8(path_bytes, "resource path")?;
        let resource_offset = cursor.read_i32_be()?;
        let stored_length = cursor.read_i32_be()?;
        let codec_bytes = cursor.read_frame(MAX_VARIANT_SIZE, false, "codec")?;
        let codec_variant = decode_utf8(codec_bytes, "codec")?;
        let layout_bytes = cursor.read_frame(MAX_VARIANT_SIZE, false, "layout")?;
        let layout_variant = decode_utf8(layout_bytes, "layout")?;
        let binding_path_bytes =
            cursor.read_frame(MAX_RESOURCE_PATH_SIZE, false, "logical binding path")?;
        let logical_binding_path = decode_utf8(binding_path_bytes, "logical binding path")?;
        cursor.require_empty()?;
        Self::new(
            identity,
            &resource_path,
            resource_offset,
            stored_length,
            &codec_variant,
            &layout_variant,
            &logical_binding_path,
        )
    }

    pub fn binding_digest(&self, locator_token: &[u8]) -> Result<Digest, PageError> {
        let locator = copy_fixed::<LOCATOR_TOKEN_SIZE>(locator_token, "locator token")?;
        let route = self.encode();
        let digest = hash_domain_framed(ROUTE_BINDING_DOMAIN, &[&route, &locator]);
        let mut route = route;
        route.fill(0);
        Ok(digest)
    }
}

impl Clone for PageRoute {
    fn clone(&self) -> Self {
        Self {
            leaf_identity: self.leaf_identity.clone(),
            resource_path: self.resource_path.clone(),
            resource_offset: self.resource_offset,
            stored_length: self.stored_length,
            codec_variant: self.codec_variant.clone(),
            layout_variant: self.layout_variant.clone(),
            logical_binding_path: self.logical_binding_path.clone(),
        }
    }
}

impl fmt::Debug for PageRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageRoute")
            .field("resource_path", &self.resource_path)
            .field("resource_offset", &self.resource_offset)
            .field("stored_length", &self.stored_length)
            .field("codec_variant", &self.codec_variant)
            .field("layout_variant", &self.layout_variant)
            .field("logical_binding_path", &self.logical_binding_path)
            .finish()
    }
}

impl Drop for PageRoute {
    fn drop(&mut self) {
        self.resource_path.clear();
        self.codec_variant.clear();
        self.layout_variant.clear();
        self.logical_binding_path.clear();
    }
}

pub type AkenRoutingMetadata = PageRoute;

fn validate_path(value: &str, field: &'static str) -> Result<(), PageError> {
    let length = value.as_bytes().len();
    if value.trim().is_empty()
        || length > MAX_RESOURCE_PATH_SIZE
        || value.contains('\0')
        || value.contains('\\')
        || value.starts_with('/')
        || value.ends_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(PageError::InvalidPath(field));
    }
    Ok(())
}

fn validate_variant(value: &str, field: &'static str) -> Result<(), PageError> {
    if value.trim().is_empty() || value.as_bytes().len() > MAX_VARIANT_SIZE || value.contains('\0')
    {
        return Err(PageError::InvalidVariant(field));
    }
    Ok(())
}

fn decode_utf8(bytes: Vec<u8>, field: &'static str) -> Result<String, PageError> {
    String::from_utf8(bytes).map_err(|_| PageError::InvalidUtf8(field))
}

#[derive(Eq, PartialEq)]
pub struct PageProof {
    leaf_identity: LeafIdentity,
    artifact_commitment: Digest,
    mesh_root: Digest,
    leaf_digest: Digest,
    siblings: Vec<Digest>,
    sibling_directions: Vec<bool>,
    call_site_proof: Vec<u8>,
    codec_variant: String,
    layout_variant: String,
}

impl PageProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        leaf_identity: LeafIdentity,
        artifact_commitment: &[u8],
        mesh_root: &[u8],
        leaf_digest: &[u8],
        siblings: Vec<Digest>,
        sibling_directions: Vec<bool>,
        call_site_proof: &[u8],
        codec_variant: &str,
        layout_variant: &str,
    ) -> Result<Self, PageError> {
        if siblings.len() != sibling_directions.len() || siblings.len() > MAX_MERKLE_DEPTH {
            return Err(PageError::InvalidInput("proof sibling count is invalid"));
        }
        if call_site_proof.is_empty() || call_site_proof.len() > MAX_CALL_SITE_PROOF_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "call-site proof",
                length: call_site_proof.len(),
                maximum: MAX_CALL_SITE_PROOF_SIZE,
            });
        }
        validate_variant(codec_variant, "codec")?;
        validate_variant(layout_variant, "layout")?;
        Ok(Self {
            leaf_identity,
            artifact_commitment: copy_fixed(artifact_commitment, "artifact commitment")?,
            mesh_root: copy_fixed(mesh_root, "mesh root")?,
            leaf_digest: copy_fixed(leaf_digest, "leaf digest")?,
            siblings,
            sibling_directions,
            call_site_proof: call_site_proof.to_vec(),
            codec_variant: codec_variant.to_owned(),
            layout_variant: layout_variant.to_owned(),
        })
    }

    pub fn leaf_identity(&self) -> &LeafIdentity {
        &self.leaf_identity
    }

    pub fn artifact_commitment(&self) -> Digest {
        self.artifact_commitment
    }

    pub const fn artifact_commitment_ref(&self) -> &Digest {
        &self.artifact_commitment
    }

    pub fn artifact_canonical_commitment(&self) -> Digest {
        self.artifact_commitment
    }

    pub fn mesh_root(&self) -> Digest {
        self.mesh_root
    }

    pub fn merkle_root(&self) -> Digest {
        self.mesh_root
    }

    pub fn leaf_digest(&self) -> Digest {
        self.leaf_digest
    }

    pub fn current_leaf_digest(&self) -> Digest {
        self.leaf_digest
    }

    pub fn siblings(&self) -> Vec<Digest> {
        self.siblings.clone()
    }

    pub fn sibling_digests(&self) -> Vec<Digest> {
        self.siblings()
    }

    pub fn sibling_directions(&self) -> Vec<bool> {
        self.sibling_directions.clone()
    }

    pub fn call_site_proof(&self) -> &[u8] {
        &self.call_site_proof
    }

    pub fn codec_variant(&self) -> &str {
        &self.codec_variant
    }

    pub fn layout_variant(&self) -> &str {
        &self.layout_variant
    }

    pub fn encode(&self) -> Vec<u8> {
        let identity = self.leaf_identity.encode();
        let maximum = MAX_PROOF_ENCODING_SIZE;
        let mut writer = Writer::new(maximum);
        writer
            .write_frame(&identity, "proof leaf identity")
            .expect("validated proof identity");
        writer
            .write(&self.artifact_commitment)
            .expect("validated proof commitment");
        writer.write(&self.mesh_root).expect("validated proof root");
        writer
            .write(&self.leaf_digest)
            .expect("validated proof leaf");
        writer
            .write_i32(self.siblings.len() as i32)
            .expect("validated proof sibling count");
        for (sibling, direction) in self.siblings.iter().zip(&self.sibling_directions) {
            writer.write(sibling).expect("validated proof sibling");
            writer
                .write_u8(u8::from(*direction))
                .expect("validated proof direction");
        }
        writer
            .write_frame(&self.call_site_proof, "call-site proof")
            .expect("validated call-site proof");
        writer
            .write_frame(self.codec_variant.as_bytes(), "codec")
            .expect("validated proof codec");
        writer
            .write_frame(self.layout_variant.as_bytes(), "layout")
            .expect("validated proof layout");
        let mut identity = identity;
        identity.fill(0);
        writer.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PageError> {
        if encoded.is_empty() || encoded.len() > MAX_PROOF_ENCODING_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "proof",
                length: encoded.len(),
                maximum: MAX_PROOF_ENCODING_SIZE,
            });
        }
        let mut cursor = Cursor::new(encoded);
        let identity_bytes = cursor.read_frame(
            MAX_LEAF_IDENTITY_ENCODING_SIZE,
            false,
            "proof leaf identity",
        )?;
        let identity = LeafIdentity::decode(&identity_bytes)?;
        let commitment = cursor.read_fixed(DIGEST_SIZE)?;
        let root = cursor.read_fixed(DIGEST_SIZE)?;
        let leaf = cursor.read_fixed(DIGEST_SIZE)?;
        let sibling_count = cursor.read_i32_be()?;
        if !(0..=MAX_MERKLE_DEPTH as i32).contains(&sibling_count) {
            return Err(PageError::InvalidInput("proof sibling count is invalid"));
        }
        let mut siblings = Vec::with_capacity(sibling_count as usize);
        let mut directions = Vec::with_capacity(sibling_count as usize);
        for _ in 0..sibling_count {
            siblings.push(copy_fixed::<DIGEST_SIZE>(
                &cursor.read_fixed(DIGEST_SIZE)?,
                "proof sibling",
            )?);
            directions.push(match cursor.read_u8()? {
                0 => false,
                1 => true,
                direction => return Err(PageError::InvalidDirection(direction)),
            });
        }
        let call_site_proof =
            cursor.read_frame(MAX_CALL_SITE_PROOF_SIZE, false, "call-site proof")?;
        let codec = decode_utf8(
            cursor.read_frame(MAX_VARIANT_SIZE, false, "codec")?,
            "codec",
        )?;
        let layout = decode_utf8(
            cursor.read_frame(MAX_VARIANT_SIZE, false, "layout")?,
            "layout",
        )?;
        cursor.require_empty()?;
        Self::new(
            identity,
            &commitment,
            &root,
            &leaf,
            siblings,
            directions,
            &call_site_proof,
            &codec,
            &layout,
        )
    }

    pub fn binding_digest(&self) -> Digest {
        let encoded = self.encode();
        let digest = hash_domain_framed(PROOF_BINDING_DOMAIN, &[&encoded]);
        let mut encoded = encoded;
        encoded.fill(0);
        digest
    }
}

impl Clone for PageProof {
    fn clone(&self) -> Self {
        Self {
            leaf_identity: self.leaf_identity.clone(),
            artifact_commitment: self.artifact_commitment,
            mesh_root: self.mesh_root,
            leaf_digest: self.leaf_digest,
            siblings: self.siblings.clone(),
            sibling_directions: self.sibling_directions.clone(),
            call_site_proof: self.call_site_proof.clone(),
            codec_variant: self.codec_variant.clone(),
            layout_variant: self.layout_variant.clone(),
        }
    }
}

impl fmt::Debug for PageProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageProof")
            .field("sibling_count", &self.siblings.len())
            .field("call_site_proof_length", &self.call_site_proof.len())
            .field("codec_variant", &self.codec_variant)
            .field("layout_variant", &self.layout_variant)
            .finish()
    }
}

impl Drop for PageProof {
    fn drop(&mut self) {
        self.artifact_commitment.fill(0);
        self.mesh_root.fill(0);
        self.leaf_digest.fill(0);
        self.siblings.iter_mut().for_each(|digest| digest.fill(0));
        self.call_site_proof.fill(0);
        self.codec_variant.clear();
        self.layout_variant.clear();
    }
}

pub type AkenSealingProofMetadata = PageProof;

#[derive(Eq, PartialEq)]
pub struct EvaluatorPlan {
    opaque: Vec<u8>,
    fingerprint: Digest,
}

impl EvaluatorPlan {
    pub fn new(opaque: &[u8], fingerprint: &[u8]) -> Result<Self, PageError> {
        if opaque.is_empty() || opaque.len() > MAX_EVALUATOR_OPAQUE_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "opaque evaluator",
                length: opaque.len(),
                maximum: MAX_EVALUATOR_OPAQUE_SIZE,
            });
        }
        Ok(Self {
            opaque: opaque.to_vec(),
            fingerprint: copy_fixed(fingerprint, "evaluator fingerprint")?,
        })
    }

    pub fn from_opaque(opaque: &[u8], fingerprint: &[u8]) -> Result<Self, PageError> {
        Self::new(opaque, fingerprint)
    }

    pub fn opaque(&self) -> &[u8] {
        &self.opaque
    }

    pub fn copy_opaque_for_native(&self) -> Vec<u8> {
        self.opaque.clone()
    }

    pub fn fingerprint(&self) -> Digest {
        self.fingerprint
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new(MAX_EVALUATOR_PLAN_ENCODING_SIZE);
        writer
            .write_frame(&self.opaque, "opaque evaluator")
            .expect("validated opaque evaluator");
        writer
            .write(&self.fingerprint)
            .expect("validated evaluator fingerprint");
        writer.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PageError> {
        if encoded.is_empty() || encoded.len() > MAX_EVALUATOR_PLAN_ENCODING_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "evaluator plan",
                length: encoded.len(),
                maximum: MAX_EVALUATOR_PLAN_ENCODING_SIZE,
            });
        }
        let mut cursor = Cursor::new(encoded);
        let opaque = cursor.read_frame(MAX_EVALUATOR_OPAQUE_SIZE, false, "opaque evaluator")?;
        let fingerprint = cursor.read_fixed(FINGERPRINT_SIZE)?;
        cursor.require_empty()?;
        Self::new(&opaque, &fingerprint)
    }

    pub fn binding_digest(&self) -> Digest {
        let encoded = self.encode();
        let digest = hash_domain_framed(HEADER_BINDING_DOMAIN, &[&encoded]);
        let mut encoded = encoded;
        encoded.fill(0);
        digest
    }
}

impl Clone for EvaluatorPlan {
    fn clone(&self) -> Self {
        Self {
            opaque: self.opaque.clone(),
            fingerprint: self.fingerprint,
        }
    }
}

impl fmt::Debug for EvaluatorPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvaluatorPlan")
            .field("opaque_length", &self.opaque.len())
            .field("fingerprint_length", &FINGERPRINT_SIZE)
            .finish()
    }
}

impl Drop for EvaluatorPlan {
    fn drop(&mut self) {
        self.opaque.fill(0);
        self.fingerprint.fill(0);
    }
}

pub type AkenRuntimeEvaluatorPlan = EvaluatorPlan;

#[derive(Eq, PartialEq)]
pub struct PageDescriptor {
    leaf_identity: LeafIdentity,
    route: PageRoute,
    proof: PageProof,
    target_page_size: i32,
    evaluator: EvaluatorPlan,
}

impl PageDescriptor {
    pub fn new(
        route: PageRoute,
        proof: PageProof,
        target_page_size: i32,
        evaluator: EvaluatorPlan,
    ) -> Result<Self, PageError> {
        let leaf_identity = route.leaf_identity().clone();
        Self::from_metadata(leaf_identity, route, proof, target_page_size, evaluator)
    }

    pub fn create(
        handle: &PageHandle,
        logical_identity: &[u8],
        route: PageRoute,
        proof: PageProof,
        target_page_size: i32,
        evaluator: EvaluatorPlan,
    ) -> Result<Self, PageError> {
        let identity = LeafIdentity::from_handle(handle, logical_identity)?;
        Self::from_metadata(identity, route, proof, target_page_size, evaluator)
    }

    pub fn from_metadata(
        leaf_identity: LeafIdentity,
        route: PageRoute,
        proof: PageProof,
        target_page_size: i32,
        evaluator: EvaluatorPlan,
    ) -> Result<Self, PageError> {
        if target_page_size <= 0 || target_page_size as usize > MAX_PAGE_FRAME_SIZE {
            return Err(PageError::InvalidInput("target page size is invalid"));
        }
        if route.leaf_identity() != &leaf_identity {
            return Err(PageError::BindingMismatch("route leaf identity"));
        }
        if proof.leaf_identity() != &leaf_identity {
            return Err(PageError::BindingMismatch("proof leaf identity"));
        }
        if route.codec_variant() != proof.codec_variant()
            || route.layout_variant() != proof.layout_variant()
        {
            return Err(PageError::BindingMismatch("route/proof codec or layout"));
        }
        if !constant_time_eq(
            &leaf_identity.evaluator_fingerprint(),
            &evaluator.fingerprint(),
        ) {
            return Err(PageError::BindingMismatch("evaluator fingerprint"));
        }
        Ok(Self {
            leaf_identity,
            route,
            proof,
            target_page_size,
            evaluator,
        })
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PageError> {
        if encoded.is_empty() || encoded.len() > MAX_DESCRIPTOR_ENCODING_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "descriptor",
                length: encoded.len(),
                maximum: MAX_DESCRIPTOR_ENCODING_SIZE,
            });
        }
        let mut cursor = Cursor::new(encoded);
        let route_bytes = cursor.read_frame(MAX_ROUTE_ENCODING_SIZE, false, "route")?;
        let route = PageRoute::decode(&route_bytes)?;
        let proof_bytes = cursor.read_frame(MAX_PROOF_ENCODING_SIZE, false, "proof")?;
        let proof = PageProof::decode(&proof_bytes)?;
        let target_page_size = cursor.read_i32_be()?;
        let evaluator_bytes =
            cursor.read_frame(MAX_EVALUATOR_PLAN_ENCODING_SIZE, false, "evaluator plan")?;
        let evaluator = EvaluatorPlan::decode(&evaluator_bytes)?;
        cursor.require_empty()?;
        let identity = route.leaf_identity().clone();
        Self::from_metadata(identity, route, proof, target_page_size, evaluator)
    }

    pub fn resource_kind(&self) -> PageKind {
        self.leaf_identity.kind()
    }

    pub fn kind(&self) -> PageKind {
        self.resource_kind()
    }

    pub fn page_index(&self) -> i32 {
        self.leaf_identity.page_index()
    }

    pub fn logical_identity(&self) -> &[u8] {
        self.leaf_identity.logical_identity()
    }

    pub fn leaf_identity(&self) -> &LeafIdentity {
        &self.leaf_identity
    }

    pub fn route(&self) -> &PageRoute {
        &self.route
    }

    pub fn proof(&self) -> &PageProof {
        &self.proof
    }

    pub fn target_page_size(&self) -> i32 {
        self.target_page_size
    }

    pub fn evaluator_plan(&self) -> &EvaluatorPlan {
        &self.evaluator
    }

    pub fn handle(&self) -> Result<PageHandle, PageError> {
        PageHandle::new(
            self.resource_kind(),
            self.page_index(),
            self.leaf_identity.handle_encoding(),
            self.leaf_identity.locator_token(),
            self.leaf_identity.evaluator_fingerprint(),
        )
    }

    pub fn matches_handle(&self, handle: &PageHandle) -> bool {
        self.leaf_identity.matches_handle(handle)
    }

    pub fn validate_binding(&self) -> Result<(), PageError> {
        Self::from_metadata(
            self.leaf_identity.clone(),
            self.route.clone(),
            self.proof.clone(),
            self.target_page_size,
            self.evaluator.clone(),
        )
        .map(|_| ())
    }

    pub fn encode(&self) -> Vec<u8> {
        let route = self.route.encode();
        let proof = self.proof.encode();
        let evaluator = self.evaluator.encode();
        let mut writer = Writer::new(MAX_DESCRIPTOR_ENCODING_SIZE);
        writer
            .write_frame(&route, "route")
            .expect("validated descriptor route");
        writer
            .write_frame(&proof, "proof")
            .expect("validated descriptor proof");
        writer
            .write_i32(self.target_page_size)
            .expect("validated target size");
        writer
            .write_frame(&evaluator, "evaluator plan")
            .expect("validated descriptor evaluator");
        let mut route = route;
        let mut proof = proof;
        let mut evaluator = evaluator;
        route.fill(0);
        proof.fill(0);
        evaluator.fill(0);
        writer.finish()
    }

    pub fn binding_digest(&self) -> Digest {
        let encoded = self.encode();
        let digest = hash_domain_framed(DESCRIPTOR_BINDING_DOMAIN, &[&encoded]);
        let mut encoded = encoded;
        encoded.fill(0);
        digest
    }
}

impl Clone for PageDescriptor {
    fn clone(&self) -> Self {
        Self {
            leaf_identity: self.leaf_identity.clone(),
            route: self.route.clone(),
            proof: self.proof.clone(),
            target_page_size: self.target_page_size,
            evaluator: self.evaluator.clone(),
        }
    }
}

impl fmt::Debug for PageDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageDescriptor")
            .field("resource_kind", &self.resource_kind())
            .field("page_index", &self.page_index())
            .field("target_page_size", &self.target_page_size)
            .finish()
    }
}

impl Drop for PageDescriptor {
    fn drop(&mut self) {
        // Child owners wipe their own opaque and proof material.
        self.target_page_size = 0;
    }
}

pub type AkenRuntimePageDescriptor = PageDescriptor;

fn runtime_binding_digest_inner(binding: &[u8]) -> Result<Digest, PageError> {
    Ok(*jsrt_crypto::RuntimeBindingDigest::compute_bytes(binding)
        .map_err(crypto_error)?
        .as_bytes())
}

pub fn runtime_binding_digest(binding: &[u8]) -> Result<Digest, PageError> {
    runtime_binding_digest_inner(binding)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeBindingDigest(Digest);

impl RuntimeBindingDigest {
    pub fn compute(binding: &[u8]) -> Result<Self, PageError> {
        Ok(Self(runtime_binding_digest_inner(binding)?))
    }

    pub const fn as_bytes(&self) -> &Digest {
        &self.0
    }

    pub const fn into_bytes(self) -> Digest {
        self.0
    }
}

pub fn authentication_tag(binding_digest: &[u8], payload: &[u8]) -> Result<Digest, PageError> {
    let digest =
        jsrt_crypto::Digest::from_slice(binding_digest).ok_or(PageError::InvalidLength {
            field: "runtime binding digest",
            expected: DIGEST_SIZE,
            actual: binding_digest.len(),
        })?;
    Ok(*jsrt_crypto::authentication_tag(&digest, payload)
        .map_err(crypto_error)?
        .as_bytes())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FrameView {
    pub digest_offset: usize,
    pub payload_offset: usize,
    pub payload_length: usize,
    pub auth_tag_offset: usize,
}

pub struct AuthenticatedFrame {
    binding_digest: Digest,
    payload: Vec<u8>,
    wiped: bool,
}

impl AuthenticatedFrame {
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn try_binding_digest(&self) -> Result<&Digest, PageError> {
        if self.wiped {
            Err(PageError::InvalidState(
                "authenticated frame has been wiped",
            ))
        } else {
            Ok(&self.binding_digest)
        }
    }

    pub fn try_payload(&self) -> Result<&[u8], PageError> {
        if self.wiped {
            Err(PageError::InvalidState(
                "authenticated frame has been wiped",
            ))
        } else {
            Ok(&self.payload)
        }
    }

    pub fn copy_payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    pub fn into_payload(mut self) -> Vec<u8> {
        let mut payload = Vec::new();
        std::mem::swap(&mut payload, &mut self.payload);
        payload
    }

    pub const fn is_wiped(&self) -> bool {
        self.wiped
    }

    pub fn wipe(&mut self) {
        self.binding_digest.fill(0);
        self.payload.fill(0);
        self.payload.clear();
        self.wiped = true;
    }
}

impl Drop for AuthenticatedFrame {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub type AkenR1AuthenticatedFrame = AuthenticatedFrame;

pub fn encode_r1_frame(binding: &[u8], payload: &[u8]) -> Result<Vec<u8>, PageError> {
    let binding = Binding::from_slice(binding).map_err(binding_error)?;
    RuntimeEnvelope::encode(&binding, payload).map_err(protocol_error)
}

pub fn locate_r1_frame(frame: &[u8]) -> Result<FrameView, PageError> {
    if frame.len() > R1_MAX_FRAME_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "runtime frame",
            length: frame.len(),
            maximum: R1_MAX_FRAME_SIZE,
        });
    }
    let mut cursor = Cursor::new(frame);
    if cursor.read_fixed(R1_MAGIC.len())? != R1_MAGIC {
        return Err(PageError::InvalidMagic);
    }
    let version = cursor.read_u8()?;
    if version != R1_VERSION {
        return Err(PageError::UnsupportedVersion(version));
    }
    let payload_length = cursor.read_u32_be()? as usize;
    if payload_length > MAX_PAYLOAD_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "runtime payload",
            length: payload_length,
            maximum: MAX_PAYLOAD_SIZE,
        });
    }
    let digest_offset = cursor.position();
    cursor.skip(DIGEST_SIZE)?;
    let payload_offset = cursor.position();
    cursor.skip(payload_length)?;
    let auth_tag_offset = cursor.position();
    cursor.skip(R1_AUTH_TAG_SIZE)?;
    cursor.require_empty()?;
    Ok(FrameView {
        digest_offset,
        payload_offset,
        payload_length,
        auth_tag_offset,
    })
}

pub fn open_r1_frame(binding: &[u8], frame: &[u8]) -> Result<AuthenticatedFrame, PageError> {
    let _ = locate_r1_frame(frame)?;
    let binding = Binding::from_slice(binding).map_err(binding_error)?;
    let opened = RuntimeEnvelope::open(&binding, frame).map_err(protocol_error)?;
    Ok(AuthenticatedFrame {
        binding_digest: *opened.binding_digest().as_bytes(),
        payload: opened.into_payload(),
        wiped: false,
    })
}

fn binding_error(error: BindingError) -> PageError {
    match error {
        BindingError::Empty => PageError::InvalidInput("AKEN-R1 runtime binding is empty"),
        BindingError::TooLarge { size } => PageError::LengthTooLarge {
            field: "runtime binding",
            length: size,
            maximum: MAX_BINDING_SIZE,
        },
    }
}

fn crypto_error(error: jsrt_crypto::CryptoError) -> PageError {
    match error {
        jsrt_crypto::CryptoError::InvalidBinding(error) => binding_error(error),
        jsrt_crypto::CryptoError::PayloadTooLarge { size, max } => PageError::LengthTooLarge {
            field: "runtime payload",
            length: size,
            maximum: max,
        },
        jsrt_crypto::CryptoError::AuthenticationFailed => PageError::AuthenticationFailed,
        _ => PageError::InvalidInput("AKEN-R1 crypto input is invalid"),
    }
}

fn protocol_error(error: ProtocolError) -> PageError {
    match error {
        ProtocolError::Truncated {
            position,
            requested,
            remaining,
        } => PageError::Truncated {
            offset: position,
            requested,
            remaining,
        },
        ProtocolError::InvalidMagic => PageError::InvalidMagic,
        ProtocolError::UnsupportedVersion(version) => PageError::UnsupportedVersion(version),
        ProtocolError::LengthOverflow => PageError::InvalidInput("runtime frame length overflow"),
        ProtocolError::FrameTooLarge { size, max } => PageError::LengthTooLarge {
            field: "runtime frame",
            length: size,
            maximum: max,
        },
        ProtocolError::TrailingBytes { remaining } => PageError::TrailingBytes { remaining },
        ProtocolError::AuthenticationFailed => PageError::AuthenticationFailed,
        ProtocolError::InvalidBinding(error) => binding_error(error),
        ProtocolError::Crypto(error) => crypto_error(error),
    }
}

pub struct AkenR1WireFormat;

impl AkenR1WireFormat {
    pub const MAGIC: [u8; 4] = R1_MAGIC;
    pub const VERSION: u8 = R1_VERSION;
    pub const DIGEST_SIZE: usize = DIGEST_SIZE;
    pub const AUTH_TAG_SIZE: usize = R1_AUTH_TAG_SIZE;
    pub const MAX_BINDING_SIZE: usize = MAX_BINDING_SIZE;
    pub const MAX_PAYLOAD_SIZE: usize = MAX_PAYLOAD_SIZE;
    pub const HEADER_SIZE: usize = R1_HEADER_SIZE;
    pub const MIN_FRAME_SIZE: usize = R1_MIN_FRAME_SIZE;
    pub const MAX_FRAME_SIZE: usize = R1_MAX_FRAME_SIZE;

    pub fn encode(binding: &[u8], payload: &[u8]) -> Result<Vec<u8>, PageError> {
        encode_r1_frame(binding, payload)
    }

    pub fn open(binding: &[u8], frame: &[u8]) -> Result<AuthenticatedFrame, PageError> {
        open_r1_frame(binding, frame)
    }

    pub fn runtime_binding_digest(binding: &[u8]) -> Result<RuntimeBindingDigest, PageError> {
        RuntimeBindingDigest::compute(binding)
    }

    pub fn authentication_tag(binding_digest: &[u8], payload: &[u8]) -> Result<Digest, PageError> {
        authentication_tag(binding_digest, payload)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EnvelopeForm {
    InlineDescriptor = 1,
    CompactLocator = 2,
}

impl EnvelopeForm {
    pub fn from_id(id: u8) -> Result<Self, PageError> {
        match id {
            1 => Ok(Self::InlineDescriptor),
            2 => Ok(Self::CompactLocator),
            other => Err(PageError::InvalidForm(other)),
        }
    }

    pub const fn id(self) -> u8 {
        self as u8
    }
}

pub type AkenNativePageEnvelopeForm = EnvelopeForm;

const ENVELOPE_FIXED_WIRE_SIZE: usize = 1
    + 8
    + 1
    + 4
    + ENCODED_HANDLE_SIZE
    + LOCATOR_TOKEN_SIZE
    + FINGERPRINT_SIZE
    + DIGEST_SIZE
    + DIGEST_SIZE
    + DIGEST_SIZE
    + DIGEST_SIZE
    + DIGEST_SIZE;
const MAX_INLINE_DESCRIPTOR_SIZE: usize = MAX_ENVELOPE_SIZE - ENVELOPE_FIXED_WIRE_SIZE - 4;

pub fn descriptor_binding(descriptor_encoding: &[u8]) -> Digest {
    hash_domain_framed(DESCRIPTOR_BINDING_DOMAIN, &[descriptor_encoding])
}

pub fn call_site_proof_binding(call_site_proof: &[u8]) -> Result<Digest, PageError> {
    if call_site_proof.is_empty() || call_site_proof.len() > MAX_CALL_SITE_PROOF_SIZE {
        return Err(PageError::LengthTooLarge {
            field: "call-site proof",
            length: call_site_proof.len(),
            maximum: MAX_CALL_SITE_PROOF_SIZE,
        });
    }
    Ok(hash_domain_framed(
        CALL_SITE_BINDING_DOMAIN,
        &[call_site_proof],
    ))
}

pub fn route_binding(route_encoding: &[u8], locator_token: &[u8]) -> Result<Digest, PageError> {
    let locator = copy_fixed::<LOCATOR_TOKEN_SIZE>(locator_token, "locator token")?;
    Ok(hash_domain_framed(
        ROUTE_BINDING_DOMAIN,
        &[route_encoding, &locator],
    ))
}

fn envelope_binding(
    form: EnvelopeForm,
    entry_token: i64,
    kind: PageKind,
    page_index: i32,
    encoded_handle: &[u8],
    locator_token: &[u8],
    evaluator_fingerprint: &[u8],
    artifact_commitment: &[u8],
    descriptor_binding_value: &[u8],
    call_site_binding_value: &[u8],
    route_binding_value: &[u8],
    inline_descriptor: Option<&[u8]>,
) -> Result<Digest, PageError> {
    let handle = copy_fixed::<ENCODED_HANDLE_SIZE>(encoded_handle, "encoded handle")?;
    let locator = copy_fixed::<LOCATOR_TOKEN_SIZE>(locator_token, "locator token")?;
    let fingerprint =
        copy_fixed::<FINGERPRINT_SIZE>(evaluator_fingerprint, "evaluator fingerprint")?;
    let commitment = copy_fixed::<DIGEST_SIZE>(artifact_commitment, "artifact commitment")?;
    let descriptor = copy_fixed::<DIGEST_SIZE>(descriptor_binding_value, "descriptor binding")?;
    let call_site = copy_fixed::<DIGEST_SIZE>(call_site_binding_value, "call-site binding")?;
    let route = copy_fixed::<DIGEST_SIZE>(route_binding_value, "route binding")?;
    if page_index < 0 {
        return Err(PageError::InvalidPageIndex(page_index));
    }
    if form == EnvelopeForm::InlineDescriptor {
        let inline =
            inline_descriptor.ok_or(PageError::InvalidInput("inline descriptor missing"))?;
        if inline.is_empty() || inline.len() > MAX_INLINE_DESCRIPTOR_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "inline descriptor",
                length: inline.len(),
                maximum: MAX_INLINE_DESCRIPTOR_SIZE,
            });
        }
    } else if inline_descriptor.is_some() {
        return Err(PageError::InvalidInput(
            "compact envelope has inline descriptor",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(ENVELOPE_BINDING_DOMAIN);
    hasher.update(&[form.id()]);
    hasher.update(&entry_token.to_be_bytes());
    hasher.update(&[kind.id()]);
    hasher.update(&page_index.to_be_bytes());
    for field in [
        handle.as_slice(),
        locator.as_slice(),
        fingerprint.as_slice(),
        commitment.as_slice(),
        descriptor.as_slice(),
        call_site.as_slice(),
        route.as_slice(),
    ] {
        update_framed_hash(&mut hasher, field)?;
    }
    if form == EnvelopeForm::InlineDescriptor {
        update_framed_hash(&mut hasher, inline_descriptor.expect("inline checked"))?;
    }
    Ok(hasher.finalize())
}

fn update_framed_hash(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), PageError> {
    let length = u32::try_from(bytes.len()).map_err(|_| PageError::LengthTooLarge {
        field: "framed binding field",
        length: bytes.len(),
        maximum: u32::MAX as usize,
    })?;
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

pub fn compute_envelope_binding(
    form: EnvelopeForm,
    entry_token: i64,
    kind: PageKind,
    page_index: i32,
    encoded_handle: &[u8],
    locator_token: &[u8],
    evaluator_fingerprint: &[u8],
    artifact_commitment: &[u8],
    descriptor_binding_value: &[u8],
    call_site_binding_value: &[u8],
    route_binding_value: &[u8],
    inline_descriptor: Option<&[u8]>,
) -> Result<Digest, PageError> {
    envelope_binding(
        form,
        entry_token,
        kind,
        page_index,
        encoded_handle,
        locator_token,
        evaluator_fingerprint,
        artifact_commitment,
        descriptor_binding_value,
        call_site_binding_value,
        route_binding_value,
        inline_descriptor,
    )
}

#[derive(Eq, PartialEq)]
pub struct PageEnvelope {
    entry_token: i64,
    kind: PageKind,
    page_index: i32,
    form: EnvelopeForm,
    encoded_handle: [u8; ENCODED_HANDLE_SIZE],
    locator_token: [u8; LOCATOR_TOKEN_SIZE],
    evaluator_fingerprint: Digest,
    artifact_commitment: Digest,
    descriptor_binding: Digest,
    call_site_proof_binding: Digest,
    route_binding: Digest,
    inline_descriptor: Option<Vec<u8>>,
    envelope_binding: Digest,
    wiped: bool,
}

impl PageEnvelope {
    pub fn create(
        entry_token: i64,
        handle: &PageHandle,
        descriptor: &PageDescriptor,
        raw_call_site_proof: &[u8],
    ) -> Result<Self, PageError> {
        if raw_call_site_proof.is_empty() || raw_call_site_proof.len() > MAX_CALL_SITE_PROOF_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "call-site proof",
                length: raw_call_site_proof.len(),
                maximum: MAX_CALL_SITE_PROOF_SIZE,
            });
        }
        if descriptor.resource_kind() != handle.kind()
            || descriptor.page_index() != handle.page_index()
        {
            return Err(PageError::BindingMismatch("descriptor/handle identity"));
        }
        if !descriptor.matches_handle(handle) {
            return Err(PageError::BindingMismatch("descriptor handle"));
        }
        if !constant_time_eq(descriptor.proof().call_site_proof(), raw_call_site_proof) {
            return Err(PageError::BindingMismatch("call-site proof"));
        }
        let descriptor_encoding = descriptor.encode();
        let route_encoding = descriptor.route().encode();
        let descriptor_digest = descriptor_binding(&descriptor_encoding);
        let proof_digest = call_site_proof_binding(raw_call_site_proof)?;
        let locator_digest = route_binding(&route_encoding, &handle.locator_token())?;
        let inline =
            if ENVELOPE_FIXED_WIRE_SIZE + 4 + descriptor_encoding.len() <= MAX_ENVELOPE_SIZE {
                Some(descriptor_encoding.clone())
            } else {
                None
            };
        let form = if inline.is_some() {
            EnvelopeForm::InlineDescriptor
        } else {
            EnvelopeForm::CompactLocator
        };
        let envelope_digest = envelope_binding(
            form,
            entry_token,
            descriptor.resource_kind(),
            descriptor.page_index(),
            &handle.encoded(),
            &handle.locator_token(),
            &handle.evaluator_fingerprint(),
            &descriptor.proof().artifact_commitment(),
            &descriptor_digest,
            &proof_digest,
            &locator_digest,
            inline.as_deref(),
        )?;
        let result = Self {
            entry_token,
            kind: descriptor.resource_kind(),
            page_index: descriptor.page_index(),
            form,
            encoded_handle: handle.encoded(),
            locator_token: handle.locator_token(),
            evaluator_fingerprint: handle.evaluator_fingerprint(),
            artifact_commitment: descriptor.proof().artifact_commitment(),
            descriptor_binding: descriptor_digest,
            call_site_proof_binding: proof_digest,
            route_binding: locator_digest,
            inline_descriptor: inline,
            envelope_binding: envelope_digest,
            wiped: false,
        };
        let mut descriptor_encoding = descriptor_encoding;
        let mut route_encoding = route_encoding;
        descriptor_encoding.fill(0);
        route_encoding.fill(0);
        result.verify_encoded_binding()?;
        Ok(result)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PageError> {
        if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_SIZE {
            return Err(PageError::LengthTooLarge {
                field: "native page envelope",
                length: encoded.len(),
                maximum: MAX_ENVELOPE_SIZE,
            });
        }
        let mut cursor = Cursor::new(encoded);
        let form = EnvelopeForm::from_id(cursor.read_u8()?)?;
        let entry_token = cursor.read_i64_be()?;
        let kind = PageKind::from_id(cursor.read_u8()?)?;
        let page_index = cursor.read_i32_be()?;
        if page_index < 0 {
            return Err(PageError::InvalidPageIndex(page_index));
        }
        let handle = copy_fixed::<ENCODED_HANDLE_SIZE>(
            &cursor.read_fixed(ENCODED_HANDLE_SIZE)?,
            "encoded handle",
        )?;
        let locator = copy_fixed::<LOCATOR_TOKEN_SIZE>(
            &cursor.read_fixed(LOCATOR_TOKEN_SIZE)?,
            "locator token",
        )?;
        let fingerprint = copy_fixed::<FINGERPRINT_SIZE>(
            &cursor.read_fixed(FINGERPRINT_SIZE)?,
            "evaluator fingerprint",
        )?;
        let commitment =
            copy_fixed::<DIGEST_SIZE>(&cursor.read_fixed(DIGEST_SIZE)?, "artifact commitment")?;
        let descriptor_digest =
            copy_fixed::<DIGEST_SIZE>(&cursor.read_fixed(DIGEST_SIZE)?, "descriptor binding")?;
        let proof_digest =
            copy_fixed::<DIGEST_SIZE>(&cursor.read_fixed(DIGEST_SIZE)?, "call-site binding")?;
        let route_digest =
            copy_fixed::<DIGEST_SIZE>(&cursor.read_fixed(DIGEST_SIZE)?, "route binding")?;
        let inline = if form == EnvelopeForm::InlineDescriptor {
            Some(cursor.read_frame(MAX_INLINE_DESCRIPTOR_SIZE, false, "inline descriptor")?)
        } else {
            None
        };
        let envelope_digest =
            copy_fixed::<DIGEST_SIZE>(&cursor.read_fixed(DIGEST_SIZE)?, "envelope binding")?;
        cursor.require_empty()?;
        let result = Self {
            entry_token,
            kind,
            page_index,
            form,
            encoded_handle: handle,
            locator_token: locator,
            evaluator_fingerprint: fingerprint,
            artifact_commitment: commitment,
            descriptor_binding: descriptor_digest,
            call_site_proof_binding: proof_digest,
            route_binding: route_digest,
            inline_descriptor: inline,
            envelope_binding: envelope_digest,
            wiped: false,
        };
        result.verify_encoded_binding()?;
        Ok(result)
    }

    fn verify_encoded_binding(&self) -> Result<(), PageError> {
        let expected = envelope_binding(
            self.form,
            self.entry_token,
            self.kind,
            self.page_index,
            &self.encoded_handle,
            &self.locator_token,
            &self.evaluator_fingerprint,
            &self.artifact_commitment,
            &self.descriptor_binding,
            &self.call_site_proof_binding,
            &self.route_binding,
            self.inline_descriptor.as_deref(),
        )?;
        if !constant_time_eq(&expected, &self.envelope_binding) {
            return Err(PageError::AuthenticationFailed);
        }
        if self.form == EnvelopeForm::InlineDescriptor {
            let descriptor = PageDescriptor::decode(
                self.inline_descriptor
                    .as_deref()
                    .ok_or(PageError::InvalidInput("inline descriptor missing"))?,
            )?;
            if !self.matches_descriptor(&descriptor) {
                return Err(PageError::BindingMismatch("inline descriptor"));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PageError> {
        self.verify_encoded_binding()?;
        let mut writer = Writer::new(MAX_ENVELOPE_SIZE);
        writer.write_u8(self.form.id())?;
        writer.write_i64(self.entry_token)?;
        writer.write_u8(self.kind.id())?;
        writer.write_i32(self.page_index)?;
        writer.write(&self.encoded_handle)?;
        writer.write(&self.locator_token)?;
        writer.write(&self.evaluator_fingerprint)?;
        writer.write(&self.artifact_commitment)?;
        writer.write(&self.descriptor_binding)?;
        writer.write(&self.call_site_proof_binding)?;
        writer.write(&self.route_binding)?;
        if self.form == EnvelopeForm::InlineDescriptor {
            writer.write_frame(
                self.inline_descriptor
                    .as_deref()
                    .ok_or(PageError::InvalidInput("inline descriptor missing"))?,
                "inline descriptor",
            )?;
        }
        writer.write(&self.envelope_binding)?;
        Ok(writer.finish())
    }

    pub fn entry_token(&self) -> i64 {
        self.entry_token
    }

    pub fn resource_kind(&self) -> PageKind {
        self.kind
    }

    pub fn kind(&self) -> PageKind {
        self.kind
    }

    pub fn page_index(&self) -> i32 {
        self.page_index
    }

    pub fn form(&self) -> EnvelopeForm {
        self.form
    }

    pub fn has_inline_descriptor(&self) -> bool {
        self.form == EnvelopeForm::InlineDescriptor
    }

    pub fn encoded_size(&self) -> Result<usize, PageError> {
        Ok(self.encode()?.len())
    }

    pub const fn is_wiped(&self) -> bool {
        self.wiped
    }

    pub fn encoded_handle(&self) -> Result<[u8; ENCODED_HANDLE_SIZE], PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.encoded_handle)
    }

    pub fn locator_token(&self) -> Result<[u8; LOCATOR_TOKEN_SIZE], PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.locator_token)
    }

    pub fn evaluator_fingerprint(&self) -> Result<Digest, PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.evaluator_fingerprint)
    }

    pub fn artifact_commitment(&self) -> Result<Digest, PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.artifact_commitment)
    }

    pub fn descriptor_binding(&self) -> Result<Digest, PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.descriptor_binding)
    }

    pub fn call_site_proof_binding(&self) -> Result<Digest, PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.call_site_proof_binding)
    }

    pub fn route_binding(&self) -> Result<Digest, PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.route_binding)
    }

    pub fn inline_descriptor(&self) -> Result<Option<Vec<u8>>, PageError> {
        if self.is_wiped() {
            return Err(PageError::InvalidState("envelope has been wiped"));
        }
        Ok(self.inline_descriptor.clone())
    }

    pub fn matches_typed_bridge_request(
        &self,
        entry_token: i64,
        encoded_handle: &[u8],
        page_index: i32,
        raw_call_site_proof: &[u8],
    ) -> bool {
        if self.is_wiped()
            || page_index < 0
            || encoded_handle.len() != ENCODED_HANDLE_SIZE
            || raw_call_site_proof.is_empty()
            || raw_call_site_proof.len() > MAX_CALL_SITE_PROOF_SIZE
        {
            return false;
        }
        let supplied_binding = match call_site_proof_binding(raw_call_site_proof) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let token_match = entry_token == 0 || self.entry_token == entry_token;
        let page_match = self.page_index == page_index;
        let handle_match = constant_time_eq(&self.encoded_handle, encoded_handle);
        let proof_match = constant_time_eq(&self.call_site_proof_binding, &supplied_binding);
        token_match && page_match && handle_match && proof_match
    }

    pub fn matches_descriptor(&self, descriptor: &PageDescriptor) -> bool {
        if self.is_wiped()
            || descriptor.resource_kind() != self.kind
            || descriptor.page_index() != self.page_index
        {
            return false;
        }
        let handle = match descriptor.handle() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let descriptor_encoding = descriptor.encode();
        let route_encoding = descriptor.route().encode();
        let candidate_descriptor = descriptor_binding(&descriptor_encoding);
        let candidate_call_site =
            match call_site_proof_binding(descriptor.proof().call_site_proof()) {
                Ok(value) => value,
                Err(_) => return false,
            };
        let candidate_route = match route_binding(&route_encoding, &handle.locator_token()) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let result = constant_time_eq(&self.encoded_handle, &handle.encoded())
            && constant_time_eq(&self.locator_token, &handle.locator_token())
            && constant_time_eq(&self.evaluator_fingerprint, &handle.evaluator_fingerprint())
            && constant_time_eq(
                &self.artifact_commitment,
                &descriptor.proof().artifact_commitment(),
            )
            && constant_time_eq(&self.descriptor_binding, &candidate_descriptor)
            && constant_time_eq(&self.call_site_proof_binding, &candidate_call_site)
            && constant_time_eq(&self.route_binding, &candidate_route);
        let mut descriptor_encoding = descriptor_encoding;
        let mut route_encoding = route_encoding;
        descriptor_encoding.fill(0);
        route_encoding.fill(0);
        result
    }

    pub fn matches_current_page(
        &self,
        entry_token: i64,
        encoded_handle: &[u8],
        page_index: i32,
        raw_call_site_proof: &[u8],
        descriptor: &PageDescriptor,
    ) -> bool {
        let request_matches = self.matches_typed_bridge_request(
            entry_token,
            encoded_handle,
            page_index,
            raw_call_site_proof,
        );
        let descriptor_matches = self.matches_descriptor(descriptor);
        request_matches && descriptor_matches
    }

    pub fn wipe(&mut self) {
        self.encoded_handle.fill(0);
        self.locator_token.fill(0);
        self.evaluator_fingerprint.fill(0);
        self.artifact_commitment.fill(0);
        self.descriptor_binding.fill(0);
        self.call_site_proof_binding.fill(0);
        self.route_binding.fill(0);
        if let Some(descriptor) = &mut self.inline_descriptor {
            descriptor.fill(0);
        }
        self.envelope_binding.fill(0);
        self.inline_descriptor = None;
        self.wiped = true;
    }
}

impl Clone for PageEnvelope {
    fn clone(&self) -> Self {
        Self {
            entry_token: self.entry_token,
            kind: self.kind,
            page_index: self.page_index,
            form: self.form,
            encoded_handle: self.encoded_handle,
            locator_token: self.locator_token,
            evaluator_fingerprint: self.evaluator_fingerprint,
            artifact_commitment: self.artifact_commitment,
            descriptor_binding: self.descriptor_binding,
            call_site_proof_binding: self.call_site_proof_binding,
            route_binding: self.route_binding,
            inline_descriptor: self.inline_descriptor.clone(),
            envelope_binding: self.envelope_binding,
            wiped: self.wiped,
        }
    }
}

impl fmt::Debug for PageEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageEnvelope")
            .field("entry_token", &self.entry_token)
            .field("kind", &self.kind)
            .field("page_index", &self.page_index)
            .field("form", &self.form)
            .field("has_inline_descriptor", &self.has_inline_descriptor())
            .finish()
    }
}

impl Drop for PageEnvelope {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub type AkenNativePageEnvelope = PageEnvelope;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocatorBinding {
    digest: Digest,
}

impl LocatorBinding {
    pub fn new(digest: &[u8]) -> Result<Self, PageError> {
        Ok(Self {
            digest: copy_fixed(digest, "locator binding")?,
        })
    }

    pub fn compute(route: &PageRoute, locator_token: &[u8]) -> Result<Self, PageError> {
        Self::new(&route.binding_digest(locator_token)?)
    }

    pub const fn as_bytes(&self) -> &Digest {
        &self.digest
    }

    pub const fn into_bytes(self) -> Digest {
        self.digest
    }

    pub fn matches(&self, other: &[u8]) -> bool {
        constant_time_eq(&self.digest, other)
    }

    pub fn validate(&self, route: &PageRoute, locator_token: &[u8]) -> Result<(), PageError> {
        let expected = route.binding_digest(locator_token)?;
        if constant_time_eq(&self.digest, &expected) {
            Ok(())
        } else {
            Err(PageError::BindingMismatch("locator route"))
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct Locator {
    route: PageRoute,
    descriptor_binding: Digest,
    binding: LocatorBinding,
}

impl Locator {
    pub fn new(route: PageRoute, descriptor_binding: &[u8]) -> Result<Self, PageError> {
        let descriptor_binding = copy_fixed(descriptor_binding, "descriptor binding")?;
        let locator = LocatorBinding::compute(&route, &route.locator_token())?;
        Ok(Self {
            route,
            descriptor_binding,
            binding: locator,
        })
    }

    pub fn for_descriptor(descriptor: &PageDescriptor) -> Result<Self, PageError> {
        let encoded = descriptor.encode();
        let digest = descriptor_binding(&encoded);
        let result = Self::new(descriptor.route().clone(), &digest);
        let mut encoded = encoded;
        encoded.fill(0);
        result
    }

    pub fn from_descriptor(descriptor: &PageDescriptor) -> Result<Self, PageError> {
        Self::for_descriptor(descriptor)
    }

    pub fn route(&self) -> &PageRoute {
        &self.route
    }

    pub fn resource_path(&self) -> &str {
        self.route.resource_path()
    }

    pub const fn resource_offset(&self) -> i32 {
        self.route.resource_offset()
    }

    pub const fn stored_length(&self) -> i32 {
        self.route.stored_length()
    }

    pub fn descriptor_binding(&self) -> Digest {
        self.descriptor_binding
    }

    pub const fn binding(&self) -> &LocatorBinding {
        &self.binding
    }

    pub fn binding_digest(&self) -> Digest {
        *self.binding.as_bytes()
    }

    pub fn validate_route(&self) -> Result<(), PageError> {
        validate_path(self.resource_path(), "resource path")?;
        validate_path(self.route.logical_binding_path(), "logical binding path")?;
        if self.resource_offset() < 0 || self.stored_length() <= 0 {
            return Err(PageError::InvalidInput("locator bounds are invalid"));
        }
        self.binding
            .validate(&self.route, &self.route.locator_token())
    }

    pub fn validate_descriptor(&self, descriptor: &PageDescriptor) -> Result<(), PageError> {
        self.validate_route()?;
        if descriptor.route() != &self.route {
            return Err(PageError::BindingMismatch("locator route"));
        }
        let encoded = descriptor.encode();
        let expected_descriptor = descriptor_binding(&encoded);
        let mut encoded = encoded;
        encoded.fill(0);
        if !constant_time_eq(&self.descriptor_binding, &expected_descriptor) {
            return Err(PageError::BindingMismatch("locator descriptor"));
        }
        Ok(())
    }

    pub fn validate_descriptor_encoding(
        &self,
        descriptor: &PageDescriptor,
        descriptor_encoding: &[u8],
    ) -> Result<(), PageError> {
        self.validate_descriptor(descriptor)?;
        let expected = descriptor_binding(descriptor_encoding);
        if constant_time_eq(&self.descriptor_binding, &expected) {
            Ok(())
        } else {
            Err(PageError::BindingMismatch("locator descriptor digest"))
        }
    }
}

impl Clone for Locator {
    fn clone(&self) -> Self {
        Self {
            route: self.route.clone(),
            descriptor_binding: self.descriptor_binding,
            binding: self.binding,
        }
    }
}

impl fmt::Debug for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Locator")
            .field("resource_path", &self.resource_path())
            .field("resource_offset", &self.resource_offset())
            .field("stored_length", &self.stored_length())
            .finish()
    }
}

impl Drop for Locator {
    fn drop(&mut self) {
        self.descriptor_binding.fill(0);
    }
}

pub type AkenLocator = Locator;
pub type AkenLocatorBinding = LocatorBinding;

/// Page-local AES-GCM schedule created by an authenticated evaluator.
///
/// The schedule is intentionally not a generic catalog key. It is consumed by
/// one [PageLease], wiped when authentication starts, and cannot be cloned or
/// serialized.
pub struct PageCipherSchedule {
    key: [u8; 32],
}

impl PageCipherSchedule {
    pub fn from_material(material: &[u8]) -> Result<Self, PageError> {
        Ok(Self {
            key: copy_fixed::<32>(material, "page cipher schedule")?,
        })
    }

    pub(crate) fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for PageCipherSchedule {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Open,
    Authenticated,
    Consumed,
    Released,
    Failed,
}

pub struct PageLeaseContext<'a> {
    pub commitment: &'a [u8],
    pub identity: &'a [u8],
    pub page_index: i32,
    pub kind: PageKind,
    pub fingerprint: &'a [u8],
    pub codec: &'a str,
    pub layout: &'a str,
    pub locator: &'a [u8],
}

impl<'a> PageLeaseContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment: &'a [u8],
        identity: &'a [u8],
        page_index: i32,
        kind: PageKind,
        fingerprint: &'a [u8],
        codec: &'a str,
        layout: &'a str,
        locator: &'a [u8],
    ) -> Self {
        Self {
            commitment,
            identity,
            page_index,
            kind,
            fingerprint,
            codec,
            layout,
            locator,
        }
    }

    pub fn from_descriptor(descriptor: &'a PageDescriptor) -> Self {
        Self {
            commitment: descriptor.proof().artifact_commitment_ref(),
            identity: descriptor.logical_identity(),
            page_index: descriptor.page_index(),
            kind: descriptor.resource_kind(),
            fingerprint: descriptor.leaf_identity().evaluator_fingerprint_ref(),
            codec: descriptor.route().codec_variant(),
            layout: descriptor.route().layout_variant(),
            locator: descriptor.leaf_identity().locator_token_ref(),
        }
    }
}

pub struct PageLease {
    state: LeaseState,
    encoded: Vec<u8>,
    schedule: Option<PageCipherSchedule>,
    payload: Option<Vec<u8>>,
}

impl PageLease {
    pub fn new(encoded: Vec<u8>, schedule: PageCipherSchedule) -> Self {
        Self {
            state: LeaseState::Open,
            encoded,
            schedule: Some(schedule),
            payload: None,
        }
    }

    pub fn open(encoded: Vec<u8>, schedule: PageCipherSchedule) -> Self {
        Self::new(encoded, schedule)
    }

    pub const fn state(&self) -> LeaseState {
        self.state
    }

    pub const fn is_authenticated(&self) -> bool {
        matches!(self.state, LeaseState::Authenticated)
    }

    pub fn is_wiped(&self) -> bool {
        self.encoded.is_empty() && self.schedule.is_none() && self.payload.is_none()
    }

    pub fn authenticate(&mut self, context: PageLeaseContext<'_>) -> Result<(), PageError> {
        if self.state != LeaseState::Open {
            return Err(PageError::InvalidState(
                "page lease can authenticate only from Open",
            ));
        }
        let schedule = self
            .schedule
            .take()
            .ok_or(PageError::InvalidState("page lease schedule is unavailable"))?;
        let result = match PageLayout::from_variant(context.layout) {
            Ok(layout) => decode_page(
                &self.encoded,
                schedule.key_bytes(),
                context.commitment,
                context.identity,
                context.page_index,
                context.kind,
                context.fingerprint,
                context.codec,
                &layout,
                context.locator,
            ),
            Err(error) => Err(error),
        };
        drop(schedule);
        self.encoded.fill(0);
        self.encoded.clear();
        match result {
            Ok(payload) => {
                self.payload = Some(payload);
                self.state = LeaseState::Authenticated;
                Ok(())
            }
            Err(error) => {
                self.state = LeaseState::Failed;
                Err(error)
            }
        }
    }

    pub fn authenticate_with_descriptor(
        &mut self,
        descriptor: &PageDescriptor,
    ) -> Result<(), PageError> {
        let context = PageLeaseContext::from_descriptor(descriptor);
        self.authenticate(context)
    }

    pub fn payload(&self) -> Result<&[u8], PageError> {
        if self.state != LeaseState::Authenticated {
            return Err(PageError::InvalidState(
                "page lease payload requires authentication",
            ));
        }
        self.payload.as_deref().ok_or(PageError::InvalidState(
            "authenticated page lease has no payload",
        ))
    }

    pub fn copy_payload(&self) -> Result<Vec<u8>, PageError> {
        Ok(self.payload()?.to_vec())
    }

    pub fn consume(&mut self) -> Result<Vec<u8>, PageError> {
        if self.state != LeaseState::Authenticated {
            return Err(PageError::InvalidState(
                "page lease can consume only from Authenticated",
            ));
        }
        self.state = LeaseState::Consumed;
        self.payload.take().ok_or(PageError::InvalidState(
            "authenticated page lease has no payload",
        ))
    }

    pub fn release(&mut self) -> Result<(), PageError> {
        match self.state {
            LeaseState::Open | LeaseState::Authenticated | LeaseState::Failed => {
                self.wipe_buffers();
                self.state = LeaseState::Released;
                Ok(())
            }
            LeaseState::Consumed => Err(PageError::InvalidState(
                "consumed page lease cannot be released",
            )),
            LeaseState::Released => Ok(()),
        }
    }

    pub fn wipe(&mut self) {
        self.wipe_buffers();
        if self.state != LeaseState::Consumed {
            self.state = LeaseState::Released;
        }
    }

    fn wipe_buffers(&mut self) {
        self.encoded.fill(0);
        self.encoded.clear();
        self.schedule.take();
        if let Some(payload) = &mut self.payload {
            payload.fill(0);
        }
        self.payload = None;
    }
}

impl Drop for PageLease {
    fn drop(&mut self) {
        self.wipe_buffers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> PageLayout {
        PageLayout::new("unit", 12, 8, false, &[9, 8, 7, 6, 5, 4, 3, 2]).expect("layout")
    }

    fn page_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, PageLayout) {
        let plain = b"authenticated page payload".to_vec();
        let key = vec![0x40; 32];
        let commitment = vec![0x10; 32];
        let identity = b"logical-page-identity".to_vec();
        let fingerprint = vec![0x20; 32];
        let locator = vec![0x30; 16];
        let layout = layout();
        let encoded = encode_page(
            &plain,
            &key,
            &commitment,
            &identity,
            3,
            PageKind::StringPage,
            &fingerprint,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &locator,
            &[0x50; NONCE_SIZE],
            &[0x61; 12],
            &[0x62; 8],
        )
        .expect("page encode");
        (encoded, key, commitment, identity, fingerprint, layout)
    }

    fn descriptor_fixture() -> (PageHandle, PageDescriptor) {
        let fingerprint = [0x22; FINGERPRINT_SIZE];
        let handle = PageHandle::new(
            PageKind::StringPage,
            3,
            [0x11; ENCODED_HANDLE_SIZE],
            [0x12; LOCATOR_TOKEN_SIZE],
            fingerprint,
        )
        .expect("handle");
        let leaf = LeafIdentity::from_handle(&handle, b"logical-page-identity").expect("leaf");
        let layout_variant = layout().variant();
        let route = PageRoute::new(
            leaf.clone(),
            "META-INF/jsrt/page",
            7,
            123,
            CANONICAL_CODEC_VARIANT,
            &layout_variant,
            "META-INF/jsrt/page",
        )
        .expect("route");
        let proof = PageProof::new(
            leaf,
            &[0x10; DIGEST_SIZE],
            &[0x13; DIGEST_SIZE],
            &[0x14; DIGEST_SIZE],
            vec![[0x15; DIGEST_SIZE], [0x16; DIGEST_SIZE]],
            vec![false, true],
            b"call-site-proof",
            CANONICAL_CODEC_VARIANT,
            &layout_variant,
        )
        .expect("proof");
        let evaluator = EvaluatorPlan::new(b"opaque-evaluator", &fingerprint).expect("evaluator");
        let descriptor = PageDescriptor::new(route, proof, 1024, evaluator).expect("descriptor");
        (handle, descriptor)
    }

    #[test]
    fn sha256_and_r1_match_current_domain_framing() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        let frame = encode_r1_frame(b"binding", b"payload").expect("R1 encode");
        assert_eq!(
            jsrt_crypto::RUNTIME_BINDING_DOMAIN,
            b"JavaShroud/AKEN-R1/RuntimeBindingDigest/v1"
        );
        assert_eq!(
            jsrt_crypto::AUTHENTICATION_DOMAIN,
            b"JavaShroud/AKEN-R1/AuthenticatedFrame/v1"
        );
        assert_eq!(
            frame,
            RuntimeEnvelope::encode(
                &Binding::from_slice(b"binding").expect("binding"),
                b"payload"
            )
            .expect("envelope")
        );
        assert_eq!(
            frame,
            [
                0x4a, 0x53, 0x52, 0x31, 0x01, 0x00, 0x00, 0x00, 0x07, 0x61, 0x1e, 0x40, 0x2b, 0x18,
                0x7c, 0x76, 0x21, 0x7b, 0x73, 0x5b, 0x5a, 0x28, 0xeb, 0x71, 0x39, 0x29, 0x64, 0x72,
                0x13, 0xca, 0x59, 0x7f, 0xa2, 0x6b, 0xf5, 0x37, 0xc4, 0x14, 0x50, 0xfe, 0xe4, 0x70,
                0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x9f, 0x96, 0xb0, 0xef, 0x98, 0x3a, 0xbd, 0xa7,
                0x0e, 0x08, 0xcd, 0x6e, 0x91, 0x38, 0xfa, 0xb3, 0x3d, 0x5d, 0x2b, 0xaa, 0xef, 0x18,
                0xe2, 0x87, 0xec, 0x24, 0xe5, 0x59, 0x1b, 0x80, 0xd1, 0x66,
            ]
        );
        assert_eq!(
            open_r1_frame(b"binding", &frame)
                .expect("R1 open")
                .payload(),
            b"payload"
        );
        assert_eq!(
            locate_r1_frame(&frame).expect("R1 location").payload_length,
            7
        );
        let mut tampered = frame.clone();
        *tampered.last_mut().expect("tag") ^= 1;
        assert!(matches!(
            open_r1_frame(b"binding", &tampered),
            Err(PageError::AuthenticationFailed)
        ));
        assert!(matches!(
            open_r1_frame(b"other", &frame),
            Err(PageError::AuthenticationFailed)
        ));
        assert!(matches!(
            locate_r1_frame(&frame[..frame.len() - 1]),
            Err(PageError::Truncated { .. })
        ));
        assert!(matches!(
            locate_r1_frame(&[frame.clone(), frame.clone()].concat()),
            Err(PageError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn aes256_gcm_matches_nist_empty_and_block_vectors() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        assert_eq!(
            gcm_encrypt(&key, &nonce, &[], &[]).expect("empty GCM"),
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b,
            ]
        );
        assert_eq!(
            gcm_encrypt(&key, &nonce, &[], &[0; 16]).expect("block GCM"),
            [
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
                0xd4, 0x8a, 0xb9, 0x19,
            ]
        );
    }

    #[test]
    fn page_round_trip_has_exact_header_offsets_and_strict_bounds() {
        assert_eq!(LOGICAL_HEADER_SIZE, 201);
        assert_eq!(OFFSET_KIND, 0);
        assert_eq!(OFFSET_PAGE_INDEX, 1);
        assert_eq!(OFFSET_PLAINTEXT_LENGTH, 5);
        assert_eq!(OFFSET_NONCE, 9);
        assert_eq!(OFFSET_COMMITMENT, 21);
        assert_eq!(OFFSET_IDENTITY_HASH, 53);
        assert_eq!(OFFSET_EVALUATOR_FINGERPRINT, 85);
        assert_eq!(OFFSET_CODEC_HASH, 117);
        assert_eq!(OFFSET_LAYOUT_HASH, 149);
        assert_eq!(OFFSET_LOCATOR, 181);
        assert_eq!(OFFSET_CIPHERTEXT_LENGTH, 197);
        let (encoded, key, commitment, identity, fingerprint, layout) = page_fixture();
        let plain = decode_page(
            &encoded,
            &key,
            &commitment,
            &identity,
            3,
            PageKind::StringPage,
            &fingerprint,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &[0x30; 16],
        )
        .expect("page decode");
        assert_eq!(plain, b"authenticated page payload");
        let header_offset = layout.header_offset(encoded.len()).expect("header offset");
        let header =
            PageHeader::decode(&encoded[header_offset..header_offset + LOGICAL_HEADER_SIZE])
                .expect("header");
        assert_eq!(header.kind(), PageKind::StringPage);
        assert_eq!(header.page_index(), 3);
        assert_eq!(header.plaintext_length(), plain.len());
        assert_eq!(header.ciphertext_length(), plain.len() + GCM_TAG_SIZE);
        for cut in [0, 1, encoded.len() - 1] {
            assert!(decode_page(
                &encoded[..cut],
                &key,
                &commitment,
                &identity,
                3,
                PageKind::StringPage,
                &fingerprint,
                CANONICAL_CODEC_VARIANT,
                &layout,
                &[0x30; 16],
            )
            .is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_page(
            &trailing,
            &key,
            &commitment,
            &identity,
            3,
            PageKind::StringPage,
            &fingerprint,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &[0x30; 16],
        )
        .is_err());
        let concatenated = [encoded.clone(), encoded].concat();
        assert!(decode_page(
            &concatenated,
            &key,
            &commitment,
            &identity,
            3,
            PageKind::StringPage,
            &fingerprint,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &[0x30; 16],
        )
        .is_err());
    }

    #[test]
    fn page_header_and_locator_tamper_fail_before_plaintext() {
        let (encoded, key, commitment, identity, fingerprint, layout) = page_fixture();
        let mut header_tamper = encoded.clone();
        header_tamper[layout.prefix_length() + OFFSET_COMMITMENT] ^= 1;
        assert_eq!(
            decode_page(
                &header_tamper,
                &key,
                &commitment,
                &identity,
                3,
                PageKind::StringPage,
                &fingerprint,
                CANONICAL_CODEC_VARIANT,
                &layout,
                &[0x30; 16],
            ),
            Err(PageError::HashMismatch("artifact commitment"))
        );
        let mut body_tamper = encoded.clone();
        body_tamper[layout.body_offset()] ^= 1;
        assert_eq!(
            decode_page(
                &body_tamper,
                &key,
                &commitment,
                &identity,
                3,
                PageKind::StringPage,
                &fingerprint,
                CANONICAL_CODEC_VARIANT,
                &layout,
                &[0x30; 16],
            ),
            Err(PageError::AuthenticationFailed)
        );
        assert!(decode_page(
            &encoded,
            &key,
            &commitment,
            &identity,
            3,
            PageKind::StringPage,
            &fingerprint,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &[0x31; 16],
        )
        .is_err());
        let mut malformed_header = vec![0u8; LOGICAL_HEADER_SIZE];
        malformed_header[OFFSET_KIND] = PageKind::StringPage.id();
        malformed_header[OFFSET_PLAINTEXT_LENGTH..OFFSET_PLAINTEXT_LENGTH + 4]
            .copy_from_slice(&i32::MAX.to_be_bytes());
        malformed_header[OFFSET_CIPHERTEXT_LENGTH..OFFSET_CIPHERTEXT_LENGTH + 4]
            .copy_from_slice(&i32::MAX.to_be_bytes());
        assert!(matches!(
            PageHeader::decode(&malformed_header),
            Err(PageError::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn descriptor_route_proof_and_evaluator_are_exact_and_bounded() {
        let (_handle, descriptor) = descriptor_fixture();
        let encoded = descriptor.encode();
        assert_eq!(
            PageDescriptor::decode(&encoded).expect("descriptor decode"),
            descriptor
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            PageDescriptor::decode(&trailing),
            Err(PageError::TrailingBytes { .. })
        ));
        let mut tampered = encoded.clone();
        *tampered.last_mut().expect("descriptor") ^= 1;
        assert!(
            PageDescriptor::decode(&tampered).is_err()
                || descriptor.binding_digest()
                    != PageDescriptor::decode(&tampered)
                        .expect("semantic parse")
                        .binding_digest()
        );
        assert!(PageRoute::new(
            descriptor.route().leaf_identity().clone(),
            "../escape",
            0,
            1,
            "codec",
            "layout",
            "safe/path",
        )
        .is_err());
        assert!(PageProof::new(
            descriptor.proof().leaf_identity().clone(),
            &[0; 32],
            &[0; 32],
            &[0; 32],
            vec![[0; 32]; MAX_MERKLE_DEPTH + 1],
            vec![false; MAX_MERKLE_DEPTH + 1],
            b"proof",
            "codec",
            "layout",
        )
        .is_err());
        let reordered = encoded.clone();
        let route_len =
            u32::from_be_bytes(reordered[..4].try_into().expect("route length")) as usize;
        let proof_start = 4 + route_len;
        let proof_len = u32::from_be_bytes(
            reordered[proof_start..proof_start + 4]
                .try_into()
                .expect("proof length"),
        ) as usize;
        let route = reordered[..4 + route_len].to_vec();
        let proof = reordered[proof_start..proof_start + 4 + proof_len].to_vec();
        let tail = reordered[proof_start + 4 + proof_len..].to_vec();
        let reordered = [proof, route, tail].concat();
        assert!(PageDescriptor::decode(&reordered).is_err());
    }

    #[test]
    fn envelope_authenticates_inline_and_compact_forms() {
        let (handle, descriptor) = descriptor_fixture();
        let envelope = PageEnvelope::create(
            0x0102_0304_0506_0708,
            &handle,
            &descriptor,
            b"call-site-proof",
        )
        .expect("envelope");
        assert_eq!(envelope.form(), EnvelopeForm::InlineDescriptor);
        let encoded = envelope.encode().expect("envelope encode");
        assert_eq!(encoded.len(), envelope.encoded_size().expect("size"));
        let decoded = PageEnvelope::decode(&encoded).expect("envelope decode");
        assert!(decoded.matches_current_page(
            0x0102_0304_0506_0708,
            &handle.encoded(),
            3,
            b"call-site-proof",
            &descriptor,
        ));
        for mutation in [0usize, 13, ENVELOPE_FIXED_WIRE_SIZE - 1, encoded.len() - 1] {
            let mut tampered = encoded.clone();
            tampered[mutation] ^= 1;
            assert!(PageEnvelope::decode(&tampered).is_err());
        }
        assert!(PageEnvelope::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(PageEnvelope::decode(&[encoded.clone(), encoded.clone()].concat()).is_err());

        let opaque = vec![0x77; 10_000];
        let evaluator =
            EvaluatorPlan::new(&opaque, &handle.evaluator_fingerprint()).expect("large evaluator");
        let compact = PageDescriptor::from_metadata(
            descriptor.leaf_identity().clone(),
            descriptor.route().clone(),
            descriptor.proof().clone(),
            descriptor.target_page_size(),
            evaluator,
        )
        .expect("compact descriptor");
        let compact_envelope = PageEnvelope::create(9, &handle, &compact, b"call-site-proof")
            .expect("compact envelope");
        assert_eq!(compact_envelope.form(), EnvelopeForm::CompactLocator);
        assert!(!compact_envelope.has_inline_descriptor());
        let compact_bytes = compact_envelope.encode().expect("compact encode");
        assert_eq!(
            PageEnvelope::decode(&compact_bytes)
                .expect("compact decode")
                .form(),
            EnvelopeForm::CompactLocator
        );
        assert!(compact_envelope.matches_descriptor(&compact));
        assert!(!compact_envelope.matches_descriptor(&descriptor));
    }

    #[test]
    fn locator_binding_is_route_and_descriptor_bound() {
        let (_handle, descriptor) = descriptor_fixture();
        let locator = Locator::for_descriptor(&descriptor).expect("locator");
        locator.validate_route().expect("route validation");
        locator
            .validate_descriptor(&descriptor)
            .expect("descriptor validation");
        let mut altered = descriptor.route().clone();
        let identity = altered.leaf_identity().clone();
        altered = PageRoute::new(
            identity,
            altered.resource_path(),
            altered.resource_offset() + 1,
            altered.stored_length(),
            altered.codec_variant(),
            altered.layout_variant(),
            altered.logical_binding_path(),
        )
        .expect("altered route");
        assert_ne!(
            locator.binding_digest(),
            LocatorBinding::compute(&altered, &altered.locator_token())
                .expect("binding")
                .into_bytes()
        );
        assert!(!locator.binding().matches(&[0; DIGEST_SIZE]));
    }

    #[test]
    fn page_keys_sort_and_reject_duplicates() {
        let first = PageKey::new(PageKind::NativeChunk, 2, &[2; 24], &[2; 16]).expect("key");
        let second = PageKey::new(PageKind::StringPage, 1, &[1; 24], &[1; 16]).expect("key");
        let third = PageKey::new(PageKind::StringPage, 0, &[1; 24], &[1; 16]).expect("key");
        let mut directory = PageDirectory::new();
        directory.insert(first.clone(), "first").expect("insert");
        directory.insert(second.clone(), "second").expect("insert");
        directory.insert(third.clone(), "third").expect("insert");
        assert_eq!(
            directory.keys().collect::<Vec<_>>(),
            vec![&third, &second, &first]
        );
        assert_eq!(directory.lookup(&second), Some(&"second"));
        assert_eq!(
            directory.insert(second, "duplicate"),
            Err(PageError::DuplicatePageKey)
        );
        assert!(PageKey::new(PageKind::Vm, -1, &[0; 24], &[0; 16]).is_err());
    }

    #[test]
    fn lease_only_exposes_authenticated_payload_and_transitions_once() {
        let (encoded, key, commitment, identity, fingerprint, layout) = page_fixture();
        let schedule = PageCipherSchedule::from_material(&key).expect("schedule");
        let mut lease = PageLease::new(encoded, schedule);
        assert_eq!(lease.state(), LeaseState::Open);
        assert_eq!(
            lease.payload(),
            Err(PageError::InvalidState(
                "page lease payload requires authentication"
            ))
        );
        lease
            .authenticate(PageLeaseContext::new(
                &commitment,
                &identity,
                3,
                PageKind::StringPage,
                &fingerprint,
                CANONICAL_CODEC_VARIANT,
                &layout.variant(),
                &[0x30; 16],
            ))
            .expect("authenticate");
        assert_eq!(lease.state(), LeaseState::Authenticated);
        assert_eq!(
            lease.payload().expect("payload"),
            b"authenticated page payload"
        );
        assert_eq!(
            lease.authenticate(PageLeaseContext::new(
                &[],
                &[],
                3,
                PageKind::StringPage,
                &[],
                "",
                "",
                &[]
            )),
            Err(PageError::InvalidState(
                "page lease can authenticate only from Open"
            ))
        );
        assert_eq!(
            lease.consume().expect("consume"),
            b"authenticated page payload"
        );
        assert_eq!(lease.state(), LeaseState::Consumed);
        assert_eq!(
            lease.consume(),
            Err(PageError::InvalidState(
                "page lease can consume only from Authenticated"
            ))
        );

        let (mut bad_encoded, bad_key, commitment, identity, fingerprint, layout) = page_fixture();
        bad_encoded[layout.body_offset()] ^= 1;
        let schedule = PageCipherSchedule::from_material(&bad_key).expect("schedule");
        let mut failed = PageLease::new(bad_encoded, schedule);
        assert!(failed
            .authenticate(PageLeaseContext::new(
                &commitment,
                &identity,
                3,
                PageKind::StringPage,
                &fingerprint,
                CANONICAL_CODEC_VARIANT,
                &layout.variant(),
                &[0x30; 16],
            ))
            .is_err());
        assert_eq!(failed.state(), LeaseState::Failed);
        failed.release().expect("release failed lease");
        assert_eq!(failed.state(), LeaseState::Released);
        assert!(failed.is_wiped());
    }
}
