#![forbid(unsafe_code)]

//! Bounded AKEN-R1 resource directory and authenticated page-frame support.
//!
//! This crate deliberately does not parse or emit the retired JSRP v8 envelope.
//! A directory authenticates a sorted set of fixed-size [`PageKey`] references;
//! a frame authenticates its generation, key, header, and stored bytes before a
//! compressed body is handed to the pure-Rust Zstandard decoder.

use ruzstd::{BlockDecodingStrategy, FrameDecoder};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

pub const PAGE_KEY_SIZE: usize = 1 + 4 + 24 + 16;
pub const DIGEST_SIZE: usize = 32;
pub const AUTH_KEY_SIZE: usize = 32;

pub const DIRECTORY_MAGIC: [u8; 4] = *b"JSD1";
pub const DIRECTORY_VERSION: u8 = 1;
pub const DIRECTORY_HEADER_SIZE: usize = 4 + 1 + 1 + 8 + 4 + 2;
pub const DIRECTORY_ENTRY_SIZE: usize = PAGE_KEY_SIZE + 8 + 4 + DIGEST_SIZE;
pub const DIRECTORY_AUTH_TAG_SIZE: usize = DIGEST_SIZE;
pub const MAX_DIRECTORY_ENTRIES: usize = 4096;
pub const MAX_DIRECTORY_SIZE: usize =
    DIRECTORY_HEADER_SIZE + DIRECTORY_ENTRY_SIZE * MAX_DIRECTORY_ENTRIES + DIRECTORY_AUTH_TAG_SIZE;

pub const FRAME_MAGIC: [u8; 4] = *b"JSF1";
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_SIZE: usize = 4 + 1 + 1 + 1 + 1 + 8 + 4 + 4 + 16;
pub const FRAME_AUTH_TAG_SIZE: usize = DIGEST_SIZE;
pub const MAX_RESOURCE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_STORED_SIZE: usize = MAX_RESOURCE_SIZE + 256 * 1024;
pub const MAX_FRAME_SIZE: usize = FRAME_HEADER_SIZE + MAX_STORED_SIZE + FRAME_AUTH_TAG_SIZE;

pub const MAX_ZSTD_WINDOW_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_ZSTD_FRAME_SIZE: usize = MAX_STORED_SIZE;

const DIRECTORY_ENTRY_SIZE_WIRE: u16 = DIRECTORY_ENTRY_SIZE as u16;
const FLAG_COMPRESSED: u8 = 1;
const DIRECTORY_AUTH_DOMAIN: &[u8] = b"JavaShroud/AKEN-R2/ResourceDirectory/v2";
const FRAME_AUTH_DOMAIN: &[u8] = b"JavaShroud/AKEN-R2/ResourceFrame/v2";
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const ZSTD_MAX_BLOCK_SIZE: usize = 128 * 1024;

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

    pub fn from_id(value: u8) -> Result<Self, ResourceError> {
        match value {
            1 => Ok(Self::Vbc4Method),
            2 => Ok(Self::StringPage),
            3 => Ok(Self::EncryptedClassPage),
            4 => Ok(Self::NativeChunk),
            other => Err(ResourceError::InvalidKind(other)),
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

/// Canonical fixed-size lookup key: kind, big-endian page index, opaque handle,
/// and opaque locator token. Its byte order is the directory sort order.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PageKey {
    bytes: Vec<u8>,
}

impl PageKey {
    pub fn new(
        kind: PageKind,
        page_index: i32,
        encoded_handle: &[u8],
        locator: &[u8],
    ) -> Result<Self, ResourceError> {
        if page_index < 0 {
            return Err(ResourceError::InvalidPageKey);
        }
        if encoded_handle.len() != 24 || locator.len() != 16 {
            return Err(ResourceError::InvalidPageKey);
        }
        let mut bytes = Vec::with_capacity(PAGE_KEY_SIZE);
        bytes.push(kind.id());
        bytes.extend_from_slice(&page_index.to_be_bytes());
        bytes.extend_from_slice(encoded_handle);
        bytes.extend_from_slice(locator);
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ResourceError> {
        if bytes.len() != PAGE_KEY_SIZE {
            return Err(ResourceError::InvalidPageKey);
        }
        PageKind::from_id(bytes[0])?;
        let page_index = i32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        if page_index < 0 {
            return Err(ResourceError::InvalidPageKey);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn kind(&self) -> PageKind {
        PageKind::from_id(self.bytes[0]).expect("PageKey validates its kind")
    }

    pub fn page_index(&self) -> i32 {
        i32::from_be_bytes([self.bytes[1], self.bytes[2], self.bytes[3], self.bytes[4]])
    }
}

impl fmt::Debug for PageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageKey")
            .field("kind", &self.kind())
            .field("page_index", &self.page_index())
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl Drop for PageKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceError {
    Truncated {
        offset: usize,
        requested: usize,
        remaining: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidFlags(u8),
    InvalidHeader,
    InvalidEntrySize(u16),
    TooManyEntries(usize),
    DirectoryTooLarge {
        size: usize,
        maximum: usize,
    },
    ResourceTooLarge {
        size: usize,
        maximum: usize,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidKind(u8),
    InvalidPageKey,
    DuplicatePageKey,
    DirectoryNotSorted,
    NotFound,
    InvalidAuthKeyLength(usize),
    AuthenticationFailed,
    DirectoryDigestMismatch,
    GenerationMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidNonce,
    ZstdMalformed,
    ZstdTrailingBytes,
    ZstdWindowTooLarge {
        window: usize,
        maximum: usize,
    },
    ZstdLengthMismatch {
        expected: usize,
        actual: usize,
    },
    ZstdDecoderPanicked,
    GenerationRetired,
    GenerationUnloaded,
    InvalidState(&'static str),
    Timeout,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                offset,
                requested,
                remaining,
            } => write!(
                f,
                "resource input truncated at {offset}: requested {requested}, {remaining} remain"
            ),
            Self::TrailingBytes { remaining } => {
                write!(f, "resource input has {remaining} trailing bytes")
            }
            Self::InvalidMagic => f.write_str("resource magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "resource version is unsupported: {version}")
            }
            Self::InvalidFlags(flags) => write!(f, "resource flags are invalid: {flags:#x}"),
            Self::InvalidHeader => f.write_str("resource header is invalid"),
            Self::InvalidEntrySize(size) => write!(f, "resource entry size is invalid: {size}"),
            Self::TooManyEntries(count) => {
                write!(f, "resource directory has too many entries: {count}")
            }
            Self::DirectoryTooLarge { size, maximum } => {
                write!(f, "resource directory is too large: {size} > {maximum}")
            }
            Self::ResourceTooLarge { size, maximum } => {
                write!(f, "resource is too large: {size} > {maximum}")
            }
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(f, "{field} length {actual} does not equal {expected}"),
            Self::InvalidKind(kind) => write!(f, "resource kind is invalid: {kind}"),
            Self::InvalidPageKey => f.write_str("resource page key is not fixed-size"),
            Self::DuplicatePageKey => f.write_str("resource directory has a duplicate page key"),
            Self::DirectoryNotSorted => f.write_str("resource directory page keys are not sorted"),
            Self::NotFound => f.write_str("resource page key was not found"),
            Self::InvalidAuthKeyLength(size) => {
                write!(f, "resource authentication key length is invalid: {size}")
            }
            Self::AuthenticationFailed => f.write_str("resource authentication failed"),
            Self::DirectoryDigestMismatch => f.write_str("directory frame digest does not match"),
            Self::GenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "resource generation mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidNonce => f.write_str("resource nonce is invalid"),
            Self::ZstdMalformed => f.write_str("Zstandard frame is malformed"),
            Self::ZstdTrailingBytes => f.write_str("Zstandard frame has trailing bytes"),
            Self::ZstdWindowTooLarge { window, maximum } => {
                write!(f, "Zstandard window is too large: {window} > {maximum}")
            }
            Self::ZstdLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "Zstandard length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ZstdDecoderPanicked => f.write_str("Zstandard decoder failed closed"),
            Self::GenerationRetired => f.write_str("resource generation is retiring"),
            Self::GenerationUnloaded => f.write_str("resource generation is unloaded"),
            Self::InvalidState(message) => f.write_str(message),
            Self::Timeout => f.write_str("resource generation unload timed out"),
        }
    }
}

impl std::error::Error for ResourceError {}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[allow(dead_code)]
const SHA256_K_LEGACY: [u32; 56] = [
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
    0xc671_78f2,
    0x1f83_d9ab,
    0x5be0_cd19,
    0xc105_9ed8,
    0x367c_d507,
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
];

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

fn sha256(bytes: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut state = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    let full_blocks = bytes.len() / 64;
    for block_index in 0..full_blocks {
        sha256_transform(
            &mut state,
            bytes[block_index * 64..block_index * 64 + 64]
                .try_into()
                .expect("64-byte block"),
        );
    }
    let remainder = &bytes[full_blocks * 64..];
    let mut block = [0u8; 64];
    block[..remainder.len()].copy_from_slice(remainder);
    block[remainder.len()] = 0x80;
    if remainder.len() >= 56 {
        sha256_transform(&mut state, &block);
        block.fill(0);
    }
    block[56..].copy_from_slice(&bit_length.to_be_bytes());
    sha256_transform(&mut state, &block);
    block.fill(0);
    let mut output = [0u8; DIGEST_SIZE];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    state.fill(0);
    output
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
    words.fill(0);
    working.fill(0);
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResourceKind {
    VmBytecode = 1,
    NativeLibrary = 2,
    Manifest = 3,
    NativeIndex = 4,
}

impl ResourceKind {
    pub const fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(value: u8) -> Result<Self, ResourceError> {
        match value {
            1 => Ok(Self::VmBytecode),
            2 => Ok(Self::NativeLibrary),
            3 => Ok(Self::Manifest),
            4 => Ok(Self::NativeIndex),
            other => Err(ResourceError::InvalidKind(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRef {
    offset: u64,
    length: u32,
    digest: [u8; DIGEST_SIZE],
}

impl ResourceRef {
    pub fn new(offset: u64, length: u32, digest: &[u8]) -> Result<Self, ResourceError> {
        let digest = copy_digest(digest, "resource digest")?;
        let length_usize = length as usize;
        if length_usize > MAX_FRAME_SIZE {
            return Err(ResourceError::ResourceTooLarge {
                size: length_usize,
                maximum: MAX_FRAME_SIZE,
            });
        }
        Ok(Self {
            offset,
            length,
            digest,
        })
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn length(&self) -> u32 {
        self.length
    }

    pub const fn digest(&self) -> &[u8; DIGEST_SIZE] {
        &self.digest
    }
}

impl Drop for ResourceRef {
    fn drop(&mut self) {
        self.digest.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    key: PageKey,
    resource: ResourceRef,
}

impl DirectoryEntry {
    pub fn new(key: PageKey, resource: ResourceRef) -> Result<Self, ResourceError> {
        require_fixed_page_key(&key)?;
        Ok(Self { key, resource })
    }

    pub fn key(&self) -> &PageKey {
        &self.key
    }

    pub const fn resource(&self) -> &ResourceRef {
        &self.resource
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceDirectory {
    generation: u64,
    entries: Vec<DirectoryEntry>,
}

impl ResourceDirectory {
    pub fn new<I>(generation: u64, entries: I) -> Result<Self, ResourceError>
    where
        I: IntoIterator<Item = DirectoryEntry>,
    {
        let mut entries: Vec<_> = entries.into_iter().collect();
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(ResourceError::TooManyEntries(entries.len()));
        }
        entries.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
        validate_sorted_entries(&entries)?;
        Ok(Self {
            generation,
            entries,
        })
    }

    pub fn from_sorted_entries(
        generation: u64,
        entries: Vec<DirectoryEntry>,
    ) -> Result<Self, ResourceError> {
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(ResourceError::TooManyEntries(entries.len()));
        }
        validate_sorted_entries(&entries)?;
        Ok(Self {
            generation,
            entries,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[DirectoryEntry] {
        &self.entries
    }

    /// Looks up a fixed page key using binary search over canonical bytes.
    pub fn lookup(&self, key: &PageKey) -> Result<&DirectoryEntry, ResourceError> {
        require_fixed_page_key(key)?;
        self.entries
            .binary_search_by(|entry| entry.key.as_bytes().cmp(key.as_bytes()))
            .map(|index| &self.entries[index])
            .map_err(|_| ResourceError::NotFound)
    }

    pub fn encoded_size(&self) -> Result<usize, ResourceError> {
        let entries_size = self.entries.len().checked_mul(DIRECTORY_ENTRY_SIZE).ok_or(
            ResourceError::DirectoryTooLarge {
                size: usize::MAX,
                maximum: MAX_DIRECTORY_SIZE,
            },
        )?;
        DIRECTORY_HEADER_SIZE
            .checked_add(entries_size)
            .and_then(|size| size.checked_add(DIRECTORY_AUTH_TAG_SIZE))
            .filter(|size| *size <= MAX_DIRECTORY_SIZE)
            .ok_or(ResourceError::DirectoryTooLarge {
                size: usize::MAX,
                maximum: MAX_DIRECTORY_SIZE,
            })
    }

    /// Encodes exactly the current authenticated R1 directory format.
    pub fn encode(&self, auth_key: &[u8]) -> Result<Vec<u8>, ResourceError> {
        require_auth_key(auth_key)?;
        let size = self.encoded_size()?;
        let mut output = Vec::with_capacity(size);
        output.extend_from_slice(&DIRECTORY_MAGIC);
        output.push(DIRECTORY_VERSION);
        output.push(0);
        output.extend_from_slice(&self.generation.to_be_bytes());
        output.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        output.extend_from_slice(&DIRECTORY_ENTRY_SIZE_WIRE.to_be_bytes());
        for entry in &self.entries {
            output.extend_from_slice(entry.key.as_bytes());
            output.extend_from_slice(&entry.resource.offset.to_be_bytes());
            output.extend_from_slice(&entry.resource.length.to_be_bytes());
            output.extend_from_slice(&entry.resource.digest);
        }
        let tag = authenticate(auth_key, DIRECTORY_AUTH_DOMAIN, &[&output]);
        output.extend_from_slice(&tag);
        let mut tag = tag;
        tag.fill(0);
        Ok(output)
    }

    /// Authenticates the complete directory before constructing any entries.
    pub fn decode(encoded: &[u8], auth_key: &[u8]) -> Result<Self, ResourceError> {
        require_auth_key(auth_key)?;
        if encoded.len() > MAX_DIRECTORY_SIZE {
            return Err(ResourceError::DirectoryTooLarge {
                size: encoded.len(),
                maximum: MAX_DIRECTORY_SIZE,
            });
        }
        let header = parse_directory_header(encoded)?;
        let entries_size = header.entry_count.checked_mul(DIRECTORY_ENTRY_SIZE).ok_or(
            ResourceError::DirectoryTooLarge {
                size: usize::MAX,
                maximum: MAX_DIRECTORY_SIZE,
            },
        )?;
        let expected_size = DIRECTORY_HEADER_SIZE
            .checked_add(entries_size)
            .and_then(|size| size.checked_add(DIRECTORY_AUTH_TAG_SIZE))
            .ok_or(ResourceError::DirectoryTooLarge {
                size: usize::MAX,
                maximum: MAX_DIRECTORY_SIZE,
            })?;
        if encoded.len() != expected_size {
            return if encoded.len() < expected_size {
                Err(ResourceError::Truncated {
                    offset: encoded.len(),
                    requested: expected_size,
                    remaining: 0,
                })
            } else {
                Err(ResourceError::TrailingBytes {
                    remaining: encoded.len() - expected_size,
                })
            };
        }
        let tag_offset = encoded.len() - DIRECTORY_AUTH_TAG_SIZE;
        let expected_tag = authenticate(auth_key, DIRECTORY_AUTH_DOMAIN, &[&encoded[..tag_offset]]);
        let valid = constant_time_equals(&expected_tag, &encoded[tag_offset..]);
        if !valid {
            return Err(ResourceError::AuthenticationFailed);
        }

        let mut cursor = Cursor::new(&encoded[..tag_offset]);
        cursor.skip(DIRECTORY_HEADER_SIZE)?;
        let mut entries = Vec::with_capacity(header.entry_count);
        for _ in 0..header.entry_count {
            let key_bytes = cursor.read_fixed(PAGE_KEY_SIZE)?;
            let key = PageKey::from_bytes(&key_bytes).map_err(|_| ResourceError::InvalidPageKey)?;
            require_fixed_page_key(&key)?;
            let offset = cursor.read_u64_be()?;
            let length = cursor.read_u32_be()?;
            let digest = cursor.read_fixed(DIGEST_SIZE)?;
            let digest = copy_digest(&digest, "resource digest")?;
            let resource = ResourceRef::new(offset, length, &digest)?;
            entries.push(DirectoryEntry::new(key, resource)?);
        }
        cursor.require_empty()?;
        Self::from_sorted_entries(header.generation, entries)
    }
}

fn validate_sorted_entries(entries: &[DirectoryEntry]) -> Result<(), ResourceError> {
    for (index, entry) in entries.iter().enumerate() {
        require_fixed_page_key(&entry.key)?;
        if let Some(previous) = index.checked_sub(1).and_then(|value| entries.get(value)) {
            match previous.key.as_bytes().cmp(entry.key.as_bytes()) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(ResourceError::DuplicatePageKey),
                std::cmp::Ordering::Greater => return Err(ResourceError::DirectoryNotSorted),
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DirectoryHeader {
    generation: u64,
    entry_count: usize,
}

fn parse_directory_header(bytes: &[u8]) -> Result<DirectoryHeader, ResourceError> {
    if bytes.len() < DIRECTORY_HEADER_SIZE + DIRECTORY_AUTH_TAG_SIZE {
        return Err(ResourceError::Truncated {
            offset: bytes.len(),
            requested: DIRECTORY_HEADER_SIZE + DIRECTORY_AUTH_TAG_SIZE,
            remaining: 0,
        });
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.read_fixed(4)? != DIRECTORY_MAGIC {
        return Err(ResourceError::InvalidMagic);
    }
    let version = cursor.read_u8()?;
    if version != DIRECTORY_VERSION {
        return Err(ResourceError::UnsupportedVersion(version));
    }
    let flags = cursor.read_u8()?;
    if flags != 0 {
        return Err(ResourceError::InvalidFlags(flags));
    }
    let generation = cursor.read_u64_be()?;
    let entry_count = cursor.read_u32_be()? as usize;
    if entry_count > MAX_DIRECTORY_ENTRIES {
        return Err(ResourceError::TooManyEntries(entry_count));
    }
    let entry_size = cursor.read_u16_be()?;
    if entry_size != DIRECTORY_ENTRY_SIZE_WIRE {
        return Err(ResourceError::InvalidEntrySize(entry_size));
    }
    Ok(DirectoryHeader {
        generation,
        entry_count,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceFrameHeader {
    generation: u64,
    kind: ResourceKind,
    compressed: bool,
    plain_length: u32,
    stored_length: u32,
    nonce: [u8; 16],
}

impl ResourceFrameHeader {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub const fn is_compressed(&self) -> bool {
        self.compressed
    }

    pub const fn plain_length(&self) -> usize {
        self.plain_length as usize
    }

    pub const fn stored_length(&self) -> usize {
        self.stored_length as usize
    }

    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
}

/// Encodes an authenticated R1 resource frame. The body is either raw bytes or
/// a generated raw/RLE Zstandard frame; no legacy JSRP header is emitted.
pub fn encode_resource(
    key: &PageKey,
    generation: u64,
    kind: ResourceKind,
    plain: &[u8],
    auth_key: &[u8],
    compress: bool,
    nonce: [u8; 16],
) -> Result<Vec<u8>, ResourceError> {
    require_fixed_page_key(key)?;
    require_auth_key(auth_key)?;
    if plain.len() > MAX_RESOURCE_SIZE {
        return Err(ResourceError::ResourceTooLarge {
            size: plain.len(),
            maximum: MAX_RESOURCE_SIZE,
        });
    }
    let compressed_candidate = if compress {
        encode_raw_or_rle_zstd(plain)?
    } else {
        Vec::new()
    };
    let use_compressed = compress && compressed_candidate.len() < plain.len();
    let stored = if use_compressed {
        compressed_candidate
    } else {
        plain.to_vec()
    };
    let stored_length =
        u32::try_from(stored.len()).map_err(|_| ResourceError::ResourceTooLarge {
            size: stored.len(),
            maximum: MAX_STORED_SIZE,
        })?;
    let plain_length = u32::try_from(plain.len()).map_err(|_| ResourceError::ResourceTooLarge {
        size: plain.len(),
        maximum: MAX_RESOURCE_SIZE,
    })?;
    let header = ResourceFrameHeader {
        generation,
        kind,
        compressed: use_compressed,
        plain_length,
        stored_length,
        nonce,
    };
    let header_bytes = encode_frame_header(&header);
    let mut output = Vec::with_capacity(FRAME_HEADER_SIZE + stored.len() + FRAME_AUTH_TAG_SIZE);
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&stored);
    let tag = authenticate(auth_key, FRAME_AUTH_DOMAIN, &[key.as_bytes(), &output]);
    output.extend_from_slice(&tag);
    let mut header_bytes = header_bytes;
    header_bytes.fill(0);
    let mut stored = stored;
    stored.fill(0);
    let mut tag = tag;
    tag.fill(0);
    Ok(output)
}

pub struct ResourceFrame;

impl ResourceFrame {
    pub fn encode(
        key: &PageKey,
        generation: u64,
        kind: ResourceKind,
        plain: &[u8],
        auth_key: &[u8],
        compress: bool,
        nonce: [u8; 16],
    ) -> Result<Vec<u8>, ResourceError> {
        encode_resource(key, generation, kind, plain, auth_key, compress, nonce)
    }

    pub fn header(encoded: &[u8]) -> Result<ResourceFrameHeader, ResourceError> {
        parse_frame(encoded).map(|view| view.header)
    }
}

/// Authenticates the complete frame before copying, interpreting, or
/// decompressing its body.
pub fn decode_resource(
    context: &mut DecoderContext,
    key: &PageKey,
    expected_generation: u64,
    encoded: &[u8],
    auth_key: &[u8],
) -> Result<Vec<u8>, ResourceError> {
    let result = decode_resource_inner(context, key, expected_generation, encoded, auth_key);
    context.reset_and_wipe();
    result
}

pub fn decode_frame(
    context: &mut DecoderContext,
    key: &PageKey,
    expected_generation: u64,
    encoded: &[u8],
    auth_key: &[u8],
) -> Result<Vec<u8>, ResourceError> {
    decode_resource(context, key, expected_generation, encoded, auth_key)
}

fn decode_resource_inner(
    context: &mut DecoderContext,
    key: &PageKey,
    expected_generation: u64,
    encoded: &[u8],
    auth_key: &[u8],
) -> Result<Vec<u8>, ResourceError> {
    require_fixed_page_key(key)?;
    require_auth_key(auth_key)?;
    let view = parse_frame(encoded)?;
    if view.header.generation != expected_generation {
        return Err(ResourceError::GenerationMismatch {
            expected: expected_generation,
            actual: view.header.generation,
        });
    }
    let tag_offset = encoded.len() - FRAME_AUTH_TAG_SIZE;
    let expected_tag = authenticate(
        auth_key,
        FRAME_AUTH_DOMAIN,
        &[key.as_bytes(), &encoded[..tag_offset]],
    );
    let valid = constant_time_equals(&expected_tag, &encoded[tag_offset..]);
    let mut expected_tag = expected_tag;
    if !valid {
        expected_tag.fill(0);
        return Err(ResourceError::AuthenticationFailed);
    }
    expected_tag.fill(0);

    let body = &encoded[FRAME_HEADER_SIZE..tag_offset];
    if view.header.compressed {
        context.decode_zstd(body, view.header.plain_length())
    } else {
        if body.len() != view.header.plain_length() {
            return Err(ResourceError::InvalidLength {
                field: "raw resource body",
                expected: view.header.plain_length(),
                actual: body.len(),
            });
        }
        Ok(body.to_vec())
    }
}

struct FrameView {
    header: ResourceFrameHeader,
}

fn parse_frame(encoded: &[u8]) -> Result<FrameView, ResourceError> {
    if encoded.len() > MAX_FRAME_SIZE {
        return Err(ResourceError::ResourceTooLarge {
            size: encoded.len(),
            maximum: MAX_FRAME_SIZE,
        });
    }
    if encoded.len() < FRAME_HEADER_SIZE + FRAME_AUTH_TAG_SIZE {
        return Err(ResourceError::Truncated {
            offset: encoded.len(),
            requested: FRAME_HEADER_SIZE + FRAME_AUTH_TAG_SIZE,
            remaining: 0,
        });
    }
    let mut cursor = Cursor::new(encoded);
    if cursor.read_fixed(4)? != FRAME_MAGIC {
        return Err(ResourceError::InvalidMagic);
    }
    let version = cursor.read_u8()?;
    if version != FRAME_VERSION {
        return Err(ResourceError::UnsupportedVersion(version));
    }
    let flags = cursor.read_u8()?;
    if flags & !FLAG_COMPRESSED != 0 {
        return Err(ResourceError::InvalidFlags(flags));
    }
    let kind = ResourceKind::from_id(cursor.read_u8()?)?;
    if cursor.read_u8()? != 0 {
        return Err(ResourceError::InvalidHeader);
    }
    let generation = cursor.read_u64_be()?;
    let plain_length = cursor.read_u32_be()?;
    let stored_length = cursor.read_u32_be()?;
    let nonce = copy_array_16(&cursor.read_fixed(16)?, "nonce")?;
    let stored_length_usize = stored_length as usize;
    let plain_length_usize = plain_length as usize;
    if plain_length_usize > MAX_RESOURCE_SIZE || stored_length_usize > MAX_STORED_SIZE {
        return Err(ResourceError::ResourceTooLarge {
            size: plain_length_usize.max(stored_length_usize),
            maximum: MAX_STORED_SIZE,
        });
    }
    let expected_size = FRAME_HEADER_SIZE
        .checked_add(stored_length_usize)
        .and_then(|size| size.checked_add(FRAME_AUTH_TAG_SIZE))
        .ok_or(ResourceError::ResourceTooLarge {
            size: usize::MAX,
            maximum: MAX_FRAME_SIZE,
        })?;
    if encoded.len() != expected_size {
        return if encoded.len() < expected_size {
            Err(ResourceError::Truncated {
                offset: encoded.len(),
                requested: expected_size,
                remaining: 0,
            })
        } else {
            Err(ResourceError::TrailingBytes {
                remaining: encoded.len() - expected_size,
            })
        };
    }
    Ok(FrameView {
        header: ResourceFrameHeader {
            generation,
            kind,
            compressed: flags & FLAG_COMPRESSED != 0,
            plain_length,
            stored_length,
            nonce,
        },
    })
}

fn encode_frame_header(header: &ResourceFrameHeader) -> Vec<u8> {
    let mut output = Vec::with_capacity(FRAME_HEADER_SIZE);
    output.extend_from_slice(&FRAME_MAGIC);
    output.push(FRAME_VERSION);
    output.push(if header.compressed {
        FLAG_COMPRESSED
    } else {
        0
    });
    output.push(header.kind.id());
    output.push(0);
    output.extend_from_slice(&header.generation.to_be_bytes());
    output.extend_from_slice(&header.plain_length.to_be_bytes());
    output.extend_from_slice(&header.stored_length.to_be_bytes());
    output.extend_from_slice(&header.nonce);
    output
}

fn require_fixed_page_key(key: &PageKey) -> Result<(), ResourceError> {
    if key.as_bytes().len() == PAGE_KEY_SIZE {
        Ok(())
    } else {
        Err(ResourceError::InvalidPageKey)
    }
}

fn require_auth_key(key: &[u8]) -> Result<(), ResourceError> {
    if key.len() == AUTH_KEY_SIZE {
        Ok(())
    } else {
        Err(ResourceError::InvalidAuthKeyLength(key.len()))
    }
}

fn copy_digest(bytes: &[u8], field: &'static str) -> Result<[u8; DIGEST_SIZE], ResourceError> {
    if bytes.len() != DIGEST_SIZE {
        return Err(ResourceError::InvalidLength {
            field,
            expected: DIGEST_SIZE,
            actual: bytes.len(),
        });
    }
    let mut result = [0u8; DIGEST_SIZE];
    result.copy_from_slice(bytes);
    Ok(result)
}

fn copy_array_16(bytes: &[u8], field: &'static str) -> Result<[u8; 16], ResourceError> {
    if bytes.len() != 16 {
        return Err(ResourceError::InvalidLength {
            field,
            expected: 16,
            actual: bytes.len(),
        });
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(bytes);
    Ok(result)
}

fn authenticate(key: &[u8], domain: &[u8], fields: &[&[u8]]) -> [u8; DIGEST_SIZE] {
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        key_block[..DIGEST_SIZE].copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0u8; 64];
    let mut outer_pad = [0u8; 64];
    for index in 0..64 {
        inner_pad[index] = key_block[index] ^ 0x36;
        outer_pad[index] = key_block[index] ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(
        64 + domain.len() + fields.iter().map(|field| field.len()).sum::<usize>(),
    );
    inner_input.extend_from_slice(&inner_pad);
    inner_input.extend_from_slice(domain);
    for field in fields {
        inner_input.extend_from_slice(field);
    }
    let inner_digest = sha256(&inner_input);
    inner_input.fill(0);
    let mut outer_input = Vec::with_capacity(64 + DIGEST_SIZE);
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner_digest);
    let result = sha256(&outer_input);
    outer_input.fill(0);
    key_block.fill(0);
    inner_pad.fill(0);
    outer_pad.fill(0);
    result
}

/// Reusable bounded decoder state. Its explicit window is wiped after every
/// operation and by [`DecoderContext::reset_and_wipe`].
pub struct DecoderContext {
    decoder: FrameDecoder,
    window: Vec<u8>,
    max_window_size: usize,
    max_frame_size: usize,
    max_plaintext_size: usize,
}

impl DecoderContext {
    pub fn new(max_window_size: usize) -> Result<Self, ResourceError> {
        Self::with_limits(DecoderLimits {
            max_window_size,
            max_frame_size: MAX_ZSTD_FRAME_SIZE,
            max_plaintext_size: MAX_RESOURCE_SIZE,
        })
    }

    pub fn with_limits(limits: DecoderLimits) -> Result<Self, ResourceError> {
        limits.validate()?;
        Ok(Self {
            decoder: FrameDecoder::new(),
            window: vec![0; limits.max_window_size.min(4096)],
            max_window_size: limits.max_window_size,
            max_frame_size: limits.max_frame_size,
            max_plaintext_size: limits.max_plaintext_size,
        })
    }

    pub fn max_window_size(&self) -> usize {
        self.max_window_size
    }

    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    pub fn window_snapshot(&self) -> Vec<u8> {
        self.window.clone()
    }

    pub fn decode_zstd(
        &mut self,
        encoded: &[u8],
        expected_length: usize,
    ) -> Result<Vec<u8>, ResourceError> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.decode_zstd_inner(encoded, expected_length)
        }));
        let result = match result {
            Ok(result) => result,
            Err(_) => Err(ResourceError::ZstdDecoderPanicked),
        };
        self.reset_and_wipe();
        result
    }

    fn decode_zstd_inner(
        &mut self,
        encoded: &[u8],
        expected_length: usize,
    ) -> Result<Vec<u8>, ResourceError> {
        if expected_length > self.max_plaintext_size {
            return Err(ResourceError::ResourceTooLarge {
                size: expected_length,
                maximum: self.max_plaintext_size,
            });
        }
        if encoded.len() > self.max_frame_size {
            return Err(ResourceError::ResourceTooLarge {
                size: encoded.len(),
                maximum: self.max_frame_size,
            });
        }
        let inspected = inspect_zstd_frame(encoded, self.max_window_size)?;
        if let Some(content_size) = inspected.content_size {
            if content_size != expected_length {
                return Err(ResourceError::ZstdLengthMismatch {
                    expected: expected_length,
                    actual: content_size,
                });
            }
        }
        self.window
            .resize(expected_length.min(self.max_window_size), 0);
        let mut normalized = normalize_zstd_frame_for_ruzstd(encoded, expected_length)?;
        let decoder_input = normalized
            .as_ref()
            .map(WipedVec::as_slice)
            .unwrap_or(encoded);
        let decoded_result = (|| {
            let mut source = decoder_input;
            self.decoder
                .init(&mut source)
                .map_err(|_| ResourceError::ZstdMalformed)?;
            self.decoder
                .decode_blocks(&mut source, BlockDecodingStrategy::All)
                .map_err(|_| ResourceError::ZstdMalformed)?;
            let mut decoded = self.decoder.collect().ok_or(ResourceError::ZstdMalformed)?;
            if !source.is_empty() {
                decoded.fill(0);
                return Err(ResourceError::ZstdTrailingBytes);
            }
            if decoded.len() != expected_length {
                let actual = decoded.len();
                decoded.fill(0);
                return Err(ResourceError::ZstdLengthMismatch {
                    expected: expected_length,
                    actual,
                });
            }
            let copy_length = decoded.len().min(self.window.len());
            self.window[..copy_length].copy_from_slice(&decoded[..copy_length]);
            Ok(decoded)
        })();
        normalized.as_mut().map(WipedVec::wipe);
        decoded_result
    }

    pub fn reset_and_wipe(&mut self) {
        self.window.fill(0);
        self.window.clear();
        self.decoder = FrameDecoder::new();
    }
}

impl Drop for DecoderContext {
    fn drop(&mut self) {
        self.reset_and_wipe();
    }
}

impl Default for DecoderContext {
    fn default() -> Self {
        Self::new(MAX_ZSTD_WINDOW_SIZE).expect("default decoder limits are valid")
    }
}

pub type ZstdDecoderContext = DecoderContext;
pub type ResourceDecoderContext = DecoderContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderLimits {
    pub max_window_size: usize,
    pub max_frame_size: usize,
    pub max_plaintext_size: usize,
}

impl Default for DecoderLimits {
    fn default() -> Self {
        Self {
            max_window_size: MAX_ZSTD_WINDOW_SIZE,
            max_frame_size: MAX_ZSTD_FRAME_SIZE,
            max_plaintext_size: MAX_RESOURCE_SIZE,
        }
    }
}

impl DecoderLimits {
    fn validate(self) -> Result<(), ResourceError> {
        if self.max_window_size == 0 || self.max_window_size > 100 * 1024 * 1024 {
            return Err(ResourceError::ZstdWindowTooLarge {
                window: self.max_window_size,
                maximum: 100 * 1024 * 1024,
            });
        }
        if self.max_frame_size == 0 || self.max_frame_size > MAX_FRAME_SIZE {
            return Err(ResourceError::ResourceTooLarge {
                size: self.max_frame_size,
                maximum: MAX_FRAME_SIZE,
            });
        }
        if self.max_plaintext_size == 0 || self.max_plaintext_size > MAX_RESOURCE_SIZE {
            return Err(ResourceError::ResourceTooLarge {
                size: self.max_plaintext_size,
                maximum: MAX_RESOURCE_SIZE,
            });
        }
        Ok(())
    }
}

struct WipedVec {
    bytes: Vec<u8>,
}

impl WipedVec {
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn wipe(&mut self) {
        self.bytes.fill(0);
    }
}

impl Drop for WipedVec {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn normalize_zstd_frame_for_ruzstd(
    _encoded: &[u8],
    _expected_length: usize,
) -> Result<Option<WipedVec>, ResourceError> {
    Ok(None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ZstdInspection {
    content_size: Option<usize>,
}

fn inspect_zstd_frame(
    bytes: &[u8],
    maximum_window: usize,
) -> Result<ZstdInspection, ResourceError> {
    if bytes.len() < 5 || bytes[..4] != ZSTD_MAGIC {
        return Err(ResourceError::ZstdMalformed);
    }
    let descriptor = bytes[4];
    if descriptor & 0x08 != 0 {
        return Err(ResourceError::ZstdMalformed);
    }
    let single_segment = descriptor & 0x20 != 0;
    let fcs_flag = descriptor >> 6;
    let dict_flag = descriptor & 0x03;
    let mut offset = 5;
    let window_size = if single_segment {
        0
    } else {
        let window_descriptor = *bytes.get(offset).ok_or(ResourceError::ZstdMalformed)?;
        offset += 1;
        let window_log = (window_descriptor >> 3) as usize + 10;
        let window_base = 1usize
            .checked_shl(window_log as u32)
            .ok_or(ResourceError::ZstdMalformed)?;
        let window_add = (window_base / 8)
            .checked_mul((window_descriptor & 7) as usize)
            .ok_or(ResourceError::ZstdMalformed)?;
        window_base
            .checked_add(window_add)
            .ok_or(ResourceError::ZstdMalformed)?
    };
    let dictionary_length = match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => return Err(ResourceError::ZstdMalformed),
    };
    if offset.checked_add(dictionary_length).is_none() || offset + dictionary_length > bytes.len() {
        return Err(ResourceError::ZstdMalformed);
    }
    offset += dictionary_length;
    let content_size_length = match (fcs_flag, single_segment) {
        (0, true) => 1,
        (0, false) => 0,
        (1, _) => 2,
        (2, _) => 4,
        (3, _) => 8,
        _ => return Err(ResourceError::ZstdMalformed),
    };
    let content_size = if content_size_length == 0 {
        None
    } else {
        let end = offset
            .checked_add(content_size_length)
            .ok_or(ResourceError::ZstdMalformed)?;
        if end > bytes.len() {
            return Err(ResourceError::ZstdMalformed);
        }
        let mut value = 0u64;
        for (index, byte) in bytes[offset..end].iter().enumerate() {
            value |= u64::from(*byte) << (index * 8);
        }
        let value = if content_size_length == 2 {
            value.checked_add(256).ok_or(ResourceError::ZstdMalformed)?
        } else {
            value
        };
        let value = usize::try_from(value).map_err(|_| ResourceError::ZstdMalformed)?;
        Some(value)
    };
    let effective_window = if single_segment {
        content_size.ok_or(ResourceError::ZstdMalformed)?
    } else {
        window_size
    };
    if effective_window > maximum_window {
        return Err(ResourceError::ZstdWindowTooLarge {
            window: effective_window,
            maximum: maximum_window,
        });
    }
    Ok(ZstdInspection { content_size })
}

/// Decodes one complete Zstandard frame through a fresh bounded context.
pub fn decode_zstd_frame(bytes: &[u8], expected_length: usize) -> Result<Vec<u8>, ResourceError> {
    DecoderContext::default().decode_zstd(bytes, expected_length)
}

/// Emits the pure raw/RLE subset used by deterministic fixtures. The decoder
/// accepts all standard Zstandard block types through `ruzstd`.
pub fn encode_raw_or_rle_zstd(bytes: &[u8]) -> Result<Vec<u8>, ResourceError> {
    if bytes.len() > MAX_RESOURCE_SIZE {
        return Err(ResourceError::ResourceTooLarge {
            size: bytes.len(),
            maximum: MAX_RESOURCE_SIZE,
        });
    }
    let mut output = Vec::with_capacity(bytes.len() + 32);
    output.extend_from_slice(&ZSTD_MAGIC);
    write_zstd_frame_header(&mut output, bytes.len());
    if bytes.is_empty() {
        write_zstd_block_header(&mut output, true, 0, 0);
    } else {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let length = ZSTD_MAX_BLOCK_SIZE.min(bytes.len() - offset);
            let last = offset + length == bytes.len();
            if repeated_byte_block(bytes, offset, length) {
                write_zstd_block_header(&mut output, last, 1, length);
                output.push(bytes[offset]);
            } else {
                write_zstd_block_header(&mut output, last, 0, length);
                output.extend_from_slice(&bytes[offset..offset + length]);
            }
            offset += length;
        }
    }
    Ok(output)
}

fn write_zstd_frame_header(output: &mut Vec<u8>, length: usize) {
    if length <= 0xff {
        output.push(0x20);
        output.push(length as u8);
    } else if length <= 0xffff + 256 {
        output.push(0x60);
        output.extend_from_slice(&((length - 256) as u16).to_le_bytes());
    } else {
        output.push(0xa0);
        output.extend_from_slice(&(length as u32).to_le_bytes());
    }
}

fn write_zstd_block_header(output: &mut Vec<u8>, last: bool, block_type: u32, size: usize) {
    let header = u32::from(last) | (block_type << 1) | ((size as u32) << 3);
    output.extend_from_slice(&header.to_le_bytes()[..3]);
}

fn repeated_byte_block(bytes: &[u8], offset: usize, length: usize) -> bool {
    length > 1
        && bytes[offset + 1..offset + length]
            .iter()
            .all(|byte| *byte == bytes[offset])
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ResourceError> {
        let range = self.require(1)?;
        self.position += 1;
        Ok(self.bytes[range.start])
    }

    fn read_u16_be(&mut self) -> Result<u16, ResourceError> {
        let range = self.require(2)?;
        self.position += 2;
        Ok(u16::from_be_bytes([
            self.bytes[range.start],
            self.bytes[range.start + 1],
        ]))
    }

    fn read_u32_be(&mut self) -> Result<u32, ResourceError> {
        let range = self.require(4)?;
        self.position += 4;
        Ok(u32::from_be_bytes([
            self.bytes[range.start],
            self.bytes[range.start + 1],
            self.bytes[range.start + 2],
            self.bytes[range.start + 3],
        ]))
    }

    fn read_u64_be(&mut self) -> Result<u64, ResourceError> {
        let range = self.require(8)?;
        self.position += 8;
        Ok(u64::from_be_bytes([
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

    fn read_fixed(&mut self, length: usize) -> Result<Vec<u8>, ResourceError> {
        let range = self.require(length)?;
        self.position += length;
        Ok(self.bytes[range].to_vec())
    }

    fn skip(&mut self, length: usize) -> Result<(), ResourceError> {
        self.require(length)?;
        self.position += length;
        Ok(())
    }

    fn require_empty(&self) -> Result<(), ResourceError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ResourceError::TrailingBytes {
                remaining: self.bytes.len() - self.position,
            })
        }
    }

    fn require(&self, length: usize) -> Result<std::ops::Range<usize>, ResourceError> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        if length > remaining {
            return Err(ResourceError::Truncated {
                offset: self.position,
                requested: length,
                remaining,
            });
        }
        Ok(self.position..self.position + length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationState {
    Active,
    Retiring,
    Unloaded,
}

struct LifecycleState {
    status: GenerationState,
    leases: usize,
}

/// Owns one authenticated directory generation and bounds its retirement.
pub struct ResourceGeneration {
    directory: ResourceDirectory,
    lifecycle: Mutex<LifecycleState>,
    changed: Condvar,
}

impl ResourceGeneration {
    pub fn new(directory: ResourceDirectory) -> Self {
        Self {
            directory,
            lifecycle: Mutex::new(LifecycleState {
                status: GenerationState::Active,
                leases: 0,
            }),
            changed: Condvar::new(),
        }
    }

    pub fn generation(&self) -> u64 {
        self.directory.generation()
    }

    pub fn directory(&self) -> &ResourceDirectory {
        &self.directory
    }

    pub fn state(&self) -> GenerationState {
        lock_unpoisoned(&self.lifecycle).status
    }

    pub fn lease_count(&self) -> usize {
        lock_unpoisoned(&self.lifecycle).leases
    }

    pub fn acquire(&self, key: &PageKey) -> Result<ResourceLease<'_>, ResourceError> {
        let mut lifecycle = lock_unpoisoned(&self.lifecycle);
        if lifecycle.status != GenerationState::Active {
            return match lifecycle.status {
                GenerationState::Retiring => Err(ResourceError::GenerationRetired),
                GenerationState::Unloaded => Err(ResourceError::GenerationUnloaded),
                GenerationState::Active => {
                    Err(ResourceError::InvalidState("generation state changed"))
                }
            };
        }
        let entry = self.directory.lookup(key)?.clone();
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(ResourceError::InvalidState("resource lease count overflow"))?;
        Ok(ResourceLease {
            generation: self,
            entry,
        })
    }

    pub fn retire(&self) -> bool {
        let mut lifecycle = lock_unpoisoned(&self.lifecycle);
        if lifecycle.status != GenerationState::Active {
            return false;
        }
        lifecycle.status = GenerationState::Retiring;
        self.changed.notify_all();
        true
    }

    pub fn try_unload(&self) -> bool {
        let mut lifecycle = lock_unpoisoned(&self.lifecycle);
        if lifecycle.status == GenerationState::Retiring && lifecycle.leases == 0 {
            lifecycle.status = GenerationState::Unloaded;
            self.changed.notify_all();
            true
        } else {
            false
        }
    }

    pub fn wait_for_unload(&self, timeout: Duration) -> Result<(), ResourceError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ResourceError::Timeout)?;
        let mut lifecycle = lock_unpoisoned(&self.lifecycle);
        loop {
            match lifecycle.status {
                GenerationState::Unloaded => return Ok(()),
                GenerationState::Active => {
                    return Err(ResourceError::InvalidState("generation is active"))
                }
                GenerationState::Retiring if lifecycle.leases == 0 => {
                    lifecycle.status = GenerationState::Unloaded;
                    self.changed.notify_all();
                    return Ok(());
                }
                GenerationState::Retiring => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ResourceError::Timeout);
                    }
                    let (next, result) = self
                        .changed
                        .wait_timeout(lifecycle, remaining)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    lifecycle = next;
                    if result.timed_out() && lifecycle.leases != 0 {
                        return Err(ResourceError::Timeout);
                    }
                }
            }
        }
    }

    fn release_lease(&self) {
        let mut lifecycle = lock_unpoisoned(&self.lifecycle);
        lifecycle.leases = lifecycle.leases.saturating_sub(1);
        self.changed.notify_all();
    }
}

pub struct ResourceLease<'a> {
    generation: &'a ResourceGeneration,
    entry: DirectoryEntry,
}

impl<'a> ResourceLease<'a> {
    pub fn generation(&self) -> u64 {
        self.generation.generation()
    }

    pub fn key(&self) -> &PageKey {
        self.entry.key()
    }

    pub fn entry(&self) -> &DirectoryEntry {
        &self.entry
    }

    pub fn open(
        &self,
        context: &mut DecoderContext,
        encoded: &[u8],
        auth_key: &[u8],
    ) -> Result<Vec<u8>, ResourceError> {
        if encoded.len() != self.entry.resource.length as usize {
            return Err(ResourceError::InvalidLength {
                field: "leased resource frame",
                expected: self.entry.resource.length as usize,
                actual: encoded.len(),
            });
        }
        let mut digest = sha256(encoded);
        let matches = constant_time_equals(&digest, &self.entry.resource.digest);
        digest.fill(0);
        if !matches {
            return Err(ResourceError::DirectoryDigestMismatch);
        }
        decode_resource(context, self.key(), self.generation(), encoded, auth_key)
    }
}

impl Drop for ResourceLease<'_> {
    fn drop(&mut self) {
        self.generation.release_lease();
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn key(index: i32) -> PageKey {
        PageKey::new(PageKind::Vbc4Method, index, &[index as u8; 24], &[0xA5; 16])
            .expect("fixed page key")
    }

    fn auth_key() -> [u8; AUTH_KEY_SIZE] {
        [0x37; AUTH_KEY_SIZE]
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                ((pair[0] as char).to_digit(16).unwrap() << 4
                    | (pair[1] as char).to_digit(16).unwrap()) as u8
            })
            .collect()
    }

    #[test]
    fn sha256_and_hmac_use_standard_vectors() {
        assert_eq!(
            sha256(b"abc").as_slice(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            authenticate(
                b"key",
                b"",
                &[b"The quick brown fox jumps over the lazy dog"]
            ),
            hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").as_slice(),
        );
    }

    #[test]
    fn directory_is_r1_only_sorted_and_binary_searchable() {
        let digest_a = sha256(b"a");
        let digest_b = sha256(b"b");
        let a = DirectoryEntry::new(key(1), ResourceRef::new(0, 4, &digest_a).unwrap()).unwrap();
        let b = DirectoryEntry::new(key(0), ResourceRef::new(4, 4, &digest_b).unwrap()).unwrap();
        let directory = ResourceDirectory::new(11, vec![a, b]).unwrap();
        assert_eq!(directory.entries()[0].key().page_index(), 0);
        let encoded = directory.encode(&auth_key()).unwrap();
        assert!(!encoded.windows(4).any(|window| window == b"JSRP"));
        let decoded = ResourceDirectory::decode(&encoded, &auth_key()).unwrap();
        assert_eq!(decoded.generation(), 11);
        assert_eq!(decoded.lookup(&key(1)).unwrap().resource().offset(), 0);
        assert!(matches!(
            decoded.lookup(&key(9)),
            Err(ResourceError::NotFound)
        ));
    }

    #[test]
    fn directory_authentication_rejects_reordering_and_tampering() {
        let digest = sha256(b"frame");
        let first = DirectoryEntry::new(key(0), ResourceRef::new(0, 5, &digest).unwrap()).unwrap();
        let second = DirectoryEntry::new(key(1), ResourceRef::new(5, 5, &digest).unwrap()).unwrap();
        let directory = ResourceDirectory::new(3, vec![first, second]).unwrap();
        let encoded = directory.encode(&auth_key()).unwrap();
        let mut tampered = encoded.clone();
        tampered[DIRECTORY_HEADER_SIZE] ^= 1;
        assert_eq!(
            ResourceDirectory::decode(&tampered, &auth_key()),
            Err(ResourceError::AuthenticationFailed)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            ResourceDirectory::decode(&trailing, &auth_key()),
            Err(ResourceError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn raw_and_rle_zstd_frames_are_bounded_and_wiped() {
        let plain = vec![0x7f; 1024];
        let frame = encode_raw_or_rle_zstd(&plain).unwrap();
        assert_eq!(frame[..4], ZSTD_MAGIC);
        let mut context = DecoderContext::new(1024 * 1024).unwrap();
        assert_eq!(context.decode_zstd(&frame, plain.len()).unwrap(), plain);
        assert!(context.window_snapshot().iter().all(|byte| *byte == 0));
        let mut malformed = frame.clone();
        malformed.pop();
        assert!(context.decode_zstd(&malformed, plain.len()).is_err());
        assert!(context.window_snapshot().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn compressed_zstd_block_decodes_without_c_or_sys_dependencies() {
        let encoded = hex("28b52ffd60ee010d0100c8636f6d7072657373656420626c6f636b207061796c6f616420010049e36a8e01");
        let expected = b"compressed block payload ".repeat(30);
        assert_eq!(
            decode_zstd_frame(&encoded, expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn malformed_trailing_and_window_frames_fail_closed() {
        let plain = b"bounded";
        let frame = encode_raw_or_rle_zstd(plain).unwrap();
        let mut trailing = frame.clone();
        trailing.push(0x44);
        assert_eq!(
            decode_zstd_frame(&trailing, plain.len()),
            Err(ResourceError::ZstdTrailingBytes)
        );
        assert!(matches!(
            decode_zstd_frame(&frame, plain.len() + 1),
            Err(ResourceError::ZstdLengthMismatch { .. })
        ));
        let mut huge_window = frame.clone();
        huge_window[4] = 0;
        huge_window.insert(5, 0xFF);
        assert!(matches!(
            DecoderContext::new(1024)
                .unwrap()
                .decode_zstd(&huge_window, plain.len()),
            Err(ResourceError::ZstdWindowTooLarge { .. }) | Err(ResourceError::ZstdMalformed)
        ));
    }

    #[test]
    fn authenticated_frame_checks_generation_before_decompression_and_wipes_context() {
        let page_key = key(0);
        let payload = vec![0x22; 4096];
        let frame = encode_resource(
            &page_key,
            7,
            ResourceKind::VmBytecode,
            &payload,
            &auth_key(),
            true,
            [9; 16],
        )
        .unwrap();
        let mut context = DecoderContext::default();
        assert_eq!(
            decode_resource(&mut context, &page_key, 8, &frame, &auth_key()),
            Err(ResourceError::GenerationMismatch {
                expected: 8,
                actual: 7
            })
        );
        assert!(context.window_snapshot().iter().all(|byte| *byte == 0));
        let mut tampered = frame.clone();
        tampered[FRAME_HEADER_SIZE] ^= 1;
        assert_eq!(
            decode_resource(&mut context, &page_key, 7, &tampered, &auth_key()),
            Err(ResourceError::AuthenticationFailed)
        );
        assert!(context.window_snapshot().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn generation_leases_retire_and_unload_with_bounded_wait() {
        let digest = sha256(b"resource");
        let entry = DirectoryEntry::new(key(0), ResourceRef::new(0, 0, &digest).unwrap()).unwrap();
        let generation = ResourceGeneration::new(ResourceDirectory::new(9, vec![entry]).unwrap());
        let lease = generation.acquire(&key(0)).unwrap();
        assert_eq!(generation.state(), GenerationState::Active);
        assert!(generation.retire());
        assert_eq!(generation.state(), GenerationState::Retiring);
        assert!(!generation.try_unload());
        drop(lease);
        generation
            .wait_for_unload(Duration::from_millis(50))
            .unwrap();
        assert_eq!(generation.state(), GenerationState::Unloaded);
        assert!(matches!(
            generation.acquire(&key(0)),
            Err(ResourceError::GenerationUnloaded)
        ));
    }

    #[test]
    fn generation_lease_can_be_released_from_another_thread() {
        let digest = sha256(b"resource");
        let entry = DirectoryEntry::new(key(0), ResourceRef::new(0, 0, &digest).unwrap()).unwrap();
        let generation = std::sync::Arc::new(ResourceGeneration::new(
            ResourceDirectory::new(1, vec![entry]).unwrap(),
        ));
        let worker_generation = generation.clone();
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let lease = worker_generation.acquire(&key(0)).unwrap();
            ready_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            drop(lease);
        });
        ready_receiver.recv().unwrap();
        generation.retire();
        assert_eq!(
            generation.wait_for_unload(Duration::from_millis(1)),
            Err(ResourceError::Timeout)
        );
        release_sender.send(()).unwrap();
        worker.join().unwrap();
        generation
            .wait_for_unload(Duration::from_millis(100))
            .unwrap();
        assert_eq!(generation.state(), GenerationState::Unloaded);
    }
}
