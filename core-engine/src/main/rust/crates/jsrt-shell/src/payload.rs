use crate::platform::SupportedTarget;
use jsrt_crypto::{constant_time_eq, sha256};
use jsrt_crypto::{Binding, BindingError};
use jsrt_page::{ProtocolError, RuntimeEnvelope};
use std::fmt;

pub const R1_PAYLOAD_MAGIC: [u8; 4] = *b"JSPM";
pub const R1_PAYLOAD_VERSION: u8 = 1;
pub const R1_PAYLOAD_PROFILE: &str = "aken-r1-rust-ffi-v1";
pub const MAX_PAYLOAD_PROFILE_BYTES: usize = 64;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ZSTD_BLOCK_SIZE: usize = 128 * 1024;
pub const MAX_ZSTD_BLOCKS: usize = 65_536;
const FIXED_MANIFEST_BYTES: usize = 4 + 1 + 1 + 1 + 1 + (4 * 32) + 2 + 4 + 4;

#[derive(Debug)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn copy(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn wipe(&mut self) {
        self.0.fill(0);
    }

    fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    None,
    Zstd,
}

impl Compression {
    const fn id(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Zstd => 1,
        }
    }

    fn parse(value: u8) -> Result<Self, PayloadError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Zstd),
            _ => Err(PayloadError::UnsupportedCompression(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadManifest {
    target: SupportedTarget,
    artifact_commitment: [u8; 32],
    native_sha256: [u8; 32],
    abi_digest: [u8; 32],
    specialization_digest: [u8; 32],
    profile: String,
    compression: Compression,
    plaintext_length: usize,
    stored_length: usize,
}

impl PayloadManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: SupportedTarget,
        artifact_commitment: [u8; 32],
        native_sha256: [u8; 32],
        abi_digest: [u8; 32],
        specialization_digest: [u8; 32],
        compression: Compression,
        plaintext_length: usize,
        stored_length: usize,
    ) -> Result<Self, PayloadError> {
        validate_lengths(plaintext_length, stored_length)?;
        Ok(Self {
            target,
            artifact_commitment,
            native_sha256,
            abi_digest,
            specialization_digest,
            profile: R1_PAYLOAD_PROFILE.to_owned(),
            compression,
            plaintext_length,
            stored_length,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_profile(
        target: SupportedTarget,
        artifact_commitment: [u8; 32],
        native_sha256: [u8; 32],
        abi_digest: [u8; 32],
        specialization_digest: [u8; 32],
        profile: &str,
        compression: Compression,
        plaintext_length: usize,
        stored_length: usize,
    ) -> Result<Self, PayloadError> {
        validate_profile(profile)?;
        validate_lengths(plaintext_length, stored_length)?;
        Ok(Self {
            target,
            artifact_commitment,
            native_sha256,
            abi_digest,
            specialization_digest,
            profile: profile.to_owned(),
            compression,
            plaintext_length,
            stored_length,
        })
    }

    pub const fn target(&self) -> SupportedTarget {
        self.target
    }

    pub const fn artifact_commitment(&self) -> &[u8; 32] {
        &self.artifact_commitment
    }

    pub const fn native_sha256(&self) -> &[u8; 32] {
        &self.native_sha256
    }

    pub const fn abi_digest(&self) -> &[u8; 32] {
        &self.abi_digest
    }

    pub const fn specialization_digest(&self) -> &[u8; 32] {
        &self.specialization_digest
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub const fn compression(&self) -> Compression {
        self.compression
    }

    pub const fn plaintext_length(&self) -> usize {
        self.plaintext_length
    }

    pub const fn stored_length(&self) -> usize {
        self.stored_length
    }

    fn encode_into(&self, stored: &[u8]) -> Result<Vec<u8>, PayloadError> {
        validate_profile(&self.profile)?;
        validate_lengths(self.plaintext_length, self.stored_length)?;
        if stored.len() != self.stored_length {
            return Err(PayloadError::LengthMismatch {
                expected: self.stored_length,
                actual: stored.len(),
            });
        }
        let profile = self.profile.as_bytes();
        let mut output = Vec::with_capacity(
            FIXED_MANIFEST_BYTES
                .checked_add(profile.len())
                .and_then(|size| size.checked_add(stored.len()))
                .ok_or(PayloadError::LengthOverflow)?,
        );
        output.extend_from_slice(&R1_PAYLOAD_MAGIC);
        output.push(R1_PAYLOAD_VERSION);
        output.push(target_id(self.target));
        output.push(self.compression.id());
        output.push(0);
        output.extend_from_slice(&self.artifact_commitment);
        output.extend_from_slice(&self.native_sha256);
        output.extend_from_slice(&self.abi_digest);
        output.extend_from_slice(&self.specialization_digest);
        output.extend_from_slice(
            &u16::try_from(profile.len())
                .map_err(|_| PayloadError::LengthOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(profile);
        output.extend_from_slice(
            &u32::try_from(self.plaintext_length)
                .map_err(|_| PayloadError::LengthOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(self.stored_length)
                .map_err(|_| PayloadError::LengthOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(stored);
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<(Self, usize), PayloadError> {
        let mut cursor = PayloadCursor::new(bytes);
        if cursor.read_fixed::<4>()? != R1_PAYLOAD_MAGIC {
            return Err(PayloadError::InvalidMagic);
        }
        let version = cursor.read_u8()?;
        if version != R1_PAYLOAD_VERSION {
            return Err(PayloadError::UnsupportedVersion(version));
        }
        let target = target_from_id(cursor.read_u8()?)?;
        let compression = Compression::parse(cursor.read_u8()?)?;
        let flags = cursor.read_u8()?;
        if flags != 0 {
            return Err(PayloadError::InvalidManifest("manifest flags"));
        }
        let artifact_commitment = cursor.read_fixed::<32>()?;
        let native_sha256 = cursor.read_fixed::<32>()?;
        let abi_digest = cursor.read_fixed::<32>()?;
        let specialization_digest = cursor.read_fixed::<32>()?;
        let profile_length = cursor.read_u16_be()? as usize;
        if profile_length == 0 || profile_length > MAX_PAYLOAD_PROFILE_BYTES {
            return Err(PayloadError::InvalidManifest("profile length"));
        }
        let profile_bytes = cursor.read_bytes(profile_length)?;
        let profile = std::str::from_utf8(profile_bytes)
            .map_err(|_| PayloadError::InvalidManifest("profile encoding"))?;
        validate_profile(profile)?;
        let plaintext_length = cursor.read_u32_be()? as usize;
        let stored_length = cursor.read_u32_be()? as usize;
        validate_lengths(plaintext_length, stored_length)?;
        let payload_offset = cursor.position();
        cursor.skip(stored_length)?;
        cursor.require_empty()?;
        Ok((
            Self {
                target,
                artifact_commitment,
                native_sha256,
                abi_digest,
                specialization_digest,
                profile: profile.to_owned(),
                compression,
                plaintext_length,
                stored_length,
            },
            payload_offset,
        ))
    }
}

pub struct PayloadEnvelope;

impl PayloadEnvelope {
    pub fn encode(
        binding: &[u8],
        manifest: &PayloadManifest,
        stored_payload: &[u8],
    ) -> Result<Vec<u8>, PayloadError> {
        let binding = Binding::from_slice(binding)?;
        let inner = manifest.encode_into(stored_payload)?;
        let frame = RuntimeEnvelope::encode(&binding, &inner)?;
        Ok(frame)
    }

    pub fn open(binding: &[u8], frame: &[u8]) -> Result<AuthenticatedPayload, PayloadError> {
        let mut decoder = R1Decompressor::new();
        Self::open_with(binding, frame, &mut decoder)
    }

    pub fn open_for_target(
        target: SupportedTarget,
        binding: &[u8],
        frame: &[u8],
    ) -> Result<AuthenticatedPayload, PayloadError> {
        let payload = Self::open(binding, frame)?;
        if payload.manifest.target != target {
            return Err(PayloadError::TargetMismatch {
                expected: target,
                actual: payload.manifest.target,
            });
        }
        Ok(payload)
    }

    pub fn open_with<D: PayloadDecompressor>(
        binding: &[u8],
        frame: &[u8],
        decompressor: &mut D,
    ) -> Result<AuthenticatedPayload, PayloadError> {
        let binding = Binding::from_slice(binding)?;
        let authenticated = RuntimeEnvelope::open(&binding, frame)?;
        let encoded = SensitiveBytes::new(authenticated.into_payload());
        let (manifest, payload_offset) = PayloadManifest::decode(encoded.as_slice())?;
        let payload_end = payload_offset
            .checked_add(manifest.stored_length)
            .ok_or(PayloadError::LengthOverflow)?;
        if payload_end > encoded.len() {
            return Err(PayloadError::Truncated);
        }
        let stored = &encoded.as_slice()[payload_offset..payload_end];
        let plaintext =
            decompressor.decompress(manifest.compression, stored, manifest.plaintext_length)?;
        if plaintext.len() != manifest.plaintext_length {
            return Err(PayloadError::LengthMismatch {
                expected: manifest.plaintext_length,
                actual: plaintext.len(),
            });
        }
        let actual_digest = sha256(plaintext.as_slice()).into_bytes();
        if !constant_time_eq(&actual_digest, &manifest.native_sha256) {
            return Err(PayloadError::PayloadDigestMismatch);
        }
        Ok(AuthenticatedPayload {
            manifest,
            plaintext,
        })
    }
}

#[derive(Debug)]
pub struct AuthenticatedPayload {
    manifest: PayloadManifest,
    plaintext: SensitiveBytes,
}

impl AuthenticatedPayload {
    pub const fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }

    pub fn plaintext(&self) -> &[u8] {
        self.plaintext.as_slice()
    }

    pub fn copy_plaintext(&self) -> Vec<u8> {
        self.plaintext.copy()
    }

    pub fn wipe(&mut self) {
        self.plaintext.wipe();
    }
}

pub trait PayloadDecompressor {
    fn decompress(
        &mut self,
        compression: Compression,
        encoded: &[u8],
        expected_length: usize,
    ) -> Result<SensitiveBytes, DecompressError>;
}

#[derive(Debug)]
pub struct R1Decompressor {
    workspace: SensitiveBytes,
}

impl R1Decompressor {
    pub fn new() -> Self {
        Self {
            workspace: SensitiveBytes::new(Vec::new()),
        }
    }

    pub fn reset_and_wipe(&mut self) {
        self.workspace.wipe();
        self.workspace.as_mut_vec().clear();
    }

    pub fn workspace_len(&self) -> usize {
        self.workspace.len()
    }

    fn decode_zstd(
        &mut self,
        encoded: &[u8],
        expected_length: usize,
    ) -> Result<SensitiveBytes, DecompressError> {
        if encoded.len() < 6 || encoded[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
            return Err(DecompressError::Malformed("zstd magic or header"));
        }
        let mut position = 4usize;
        let descriptor = encoded[position];
        position += 1;
        if descriptor & 0x18 != 0 {
            return Err(DecompressError::Malformed("zstd reserved header bits"));
        }
        let single_segment = descriptor & 0x20 != 0;
        let checksum = descriptor & 0x04 != 0;
        let dictionary_size = match descriptor & 0x03 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if !single_segment {
            let window_descriptor = *encoded.get(position).ok_or(DecompressError::Truncated)?;
            position += 1;
            let exponent = (window_descriptor >> 3) as u32 + 10;
            if exponent >= 63 {
                return Err(DecompressError::WindowTooLarge);
            }
            let base = 1u64 << exponent;
            let additional = (base / 8) * u64::from(window_descriptor & 7);
            let window = base
                .checked_add(additional)
                .ok_or(DecompressError::WindowTooLarge)?;
            if window > MAX_PAYLOAD_BYTES as u64 {
                return Err(DecompressError::WindowTooLarge);
            }
        }
        let frame_content_size_flag = descriptor >> 6;
        let frame_content_size_bytes = match frame_content_size_flag {
            0 if single_segment => 1,
            0 => 0,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        if dictionary_size != 0 {
            return Err(DecompressError::UnsupportedDictionary);
        }
        if position
            .checked_add(dictionary_size)
            .and_then(|value| value.checked_add(frame_content_size_bytes))
            .ok_or(DecompressError::LengthOverflow)?
            > encoded.len()
        {
            return Err(DecompressError::Truncated);
        }
        position += dictionary_size;
        let declared_length = match frame_content_size_bytes {
            0 => None,
            1 => Some(u64::from(encoded[position])),
            2 => Some(
                u64::from(u16::from_le_bytes([
                    encoded[position],
                    encoded[position + 1],
                ])) + 256,
            ),
            4 => Some(u64::from(u32::from_le_bytes([
                encoded[position],
                encoded[position + 1],
                encoded[position + 2],
                encoded[position + 3],
            ]))),
            8 => Some(u64::from_le_bytes([
                encoded[position],
                encoded[position + 1],
                encoded[position + 2],
                encoded[position + 3],
                encoded[position + 4],
                encoded[position + 5],
                encoded[position + 6],
                encoded[position + 7],
            ])),
            _ => return Err(DecompressError::Malformed("zstd content size width")),
        };
        position += frame_content_size_bytes;
        if let Some(length) = declared_length {
            if length != expected_length as u64 {
                return Err(DecompressError::LengthMismatch {
                    expected: expected_length,
                    actual: usize::try_from(length).unwrap_or(usize::MAX),
                });
            }
        }
        let mut output = SensitiveBytes::new(Vec::new());
        let mut blocks = 0usize;
        let mut last = false;
        while !last {
            if blocks >= MAX_ZSTD_BLOCKS
                || position
                    .checked_add(3)
                    .ok_or(DecompressError::LengthOverflow)?
                    > encoded.len()
            {
                return Err(DecompressError::Truncated);
            }
            let header = u32::from_le_bytes([
                encoded[position],
                encoded[position + 1],
                encoded[position + 2],
                0,
            ]);
            position += 3;
            last = header & 1 != 0;
            let block_type = (header >> 1) & 3;
            let block_size = (header >> 3) as usize;
            if block_size > MAX_ZSTD_BLOCK_SIZE {
                return Err(DecompressError::BlockTooLarge);
            }
            match block_type {
                0 => {
                    let end = position
                        .checked_add(block_size)
                        .ok_or(DecompressError::LengthOverflow)?;
                    if end > encoded.len() {
                        return Err(DecompressError::Truncated);
                    }
                    append_bounded(&mut output, &encoded[position..end], expected_length)?;
                    position = end;
                }
                1 => {
                    let byte = *encoded.get(position).ok_or(DecompressError::Truncated)?;
                    position += 1;
                    append_repeat(&mut output, byte, block_size, expected_length)?;
                }
                2 => return Err(DecompressError::UnsupportedBlockType),
                _ => return Err(DecompressError::Malformed("zstd reserved block type")),
            }
            blocks += 1;
        }
        if checksum {
            let end = position
                .checked_add(4)
                .ok_or(DecompressError::LengthOverflow)?;
            if end > encoded.len() {
                return Err(DecompressError::Truncated);
            }
            let expected_checksum = u32::from_le_bytes([
                encoded[position],
                encoded[position + 1],
                encoded[position + 2],
                encoded[position + 3],
            ]);
            if xxhash32(output.as_slice()) != expected_checksum {
                return Err(DecompressError::ChecksumMismatch);
            }
            position = end;
        }
        if position != encoded.len() {
            return Err(DecompressError::TrailingBytes);
        }
        if output.len() != expected_length {
            return Err(DecompressError::LengthMismatch {
                expected: expected_length,
                actual: output.len(),
            });
        }
        self.workspace
            .as_mut_vec()
            .extend_from_slice(output.as_slice());
        Ok(output)
    }
}

impl Default for R1Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadDecompressor for R1Decompressor {
    fn decompress(
        &mut self,
        compression: Compression,
        encoded: &[u8],
        expected_length: usize,
    ) -> Result<SensitiveBytes, DecompressError> {
        self.reset_and_wipe();
        let result = match compression {
            Compression::None => {
                if encoded.len() != expected_length {
                    Err(DecompressError::LengthMismatch {
                        expected: expected_length,
                        actual: encoded.len(),
                    })
                } else {
                    Ok(SensitiveBytes::new(encoded.to_vec()))
                }
            }
            Compression::Zstd => self.decode_zstd(encoded, expected_length),
        };
        if result.is_err() {
            self.reset_and_wipe();
        }
        result
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecompressError {
    Malformed(&'static str),
    Truncated,
    TrailingBytes,
    LengthOverflow,
    LengthMismatch { expected: usize, actual: usize },
    WindowTooLarge,
    BlockTooLarge,
    UnsupportedDictionary,
    UnsupportedBlockType,
    ChecksumMismatch,
}

impl fmt::Display for DecompressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(formatter, "malformed compressed payload: {reason}"),
            Self::Truncated => formatter.write_str("compressed payload is truncated"),
            Self::TrailingBytes => formatter.write_str("compressed payload has trailing bytes"),
            Self::LengthOverflow => formatter.write_str("compressed payload length overflows"),
            Self::LengthMismatch { expected, actual } => {
                write!(
                    formatter,
                    "decompressed length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::WindowTooLarge => formatter.write_str("compressed payload window is too large"),
            Self::BlockTooLarge => formatter.write_str("compressed payload block is too large"),
            Self::UnsupportedDictionary => {
                formatter.write_str("compressed payload dictionary is unsupported")
            }
            Self::UnsupportedBlockType => {
                formatter.write_str("compressed payload block type is unsupported")
            }
            Self::ChecksumMismatch => formatter.write_str("compressed payload checksum mismatch"),
        }
    }
}

impl std::error::Error for DecompressError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadError {
    InvalidBinding(BindingError),
    Protocol(ProtocolError),
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedCompression(u8),
    InvalidManifest(&'static str),
    Truncated,
    TrailingBytes,
    LengthOverflow,
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    TargetMismatch {
        expected: SupportedTarget,
        actual: SupportedTarget,
    },
    PayloadDigestMismatch,
    Decompression(DecompressError),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
            Self::InvalidMagic => formatter.write_str("R1 payload manifest magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "R1 payload version is unsupported: {version}")
            }
            Self::UnsupportedCompression(codec) => {
                write!(formatter, "R1 payload compression is unsupported: {codec}")
            }
            Self::InvalidManifest(reason) => {
                write!(formatter, "R1 payload manifest is invalid: {reason}")
            }
            Self::Truncated => formatter.write_str("R1 payload manifest is truncated"),
            Self::TrailingBytes => formatter.write_str("R1 payload manifest has trailing bytes"),
            Self::LengthOverflow => formatter.write_str("R1 payload manifest length overflows"),
            Self::LengthMismatch { expected, actual } => {
                write!(
                    formatter,
                    "R1 payload length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::TargetMismatch { expected, actual } => {
                write!(
                    formatter,
                    "R1 payload target mismatch: expected {}, got {}",
                    expected.triple(),
                    actual.triple()
                )
            }
            Self::PayloadDigestMismatch => formatter.write_str("R1 payload digest mismatch"),
            Self::Decompression(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PayloadError {}

impl From<BindingError> for PayloadError {
    fn from(error: BindingError) -> Self {
        Self::InvalidBinding(error)
    }
}

impl From<ProtocolError> for PayloadError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<DecompressError> for PayloadError {
    fn from(error: DecompressError) -> Self {
        Self::Decompression(error)
    }
}

struct PayloadCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PayloadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn read_u8(&mut self) -> Result<u8, PayloadError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16_be(&mut self) -> Result<u16, PayloadError> {
        Ok(u16::from_be_bytes(self.read_fixed()?))
    }

    fn read_u32_be(&mut self) -> Result<u32, PayloadError> {
        Ok(u32::from_be_bytes(self.read_fixed()?))
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], PayloadError> {
        let value = self.take(N)?;
        let mut output = [0u8; N];
        output.copy_from_slice(value);
        Ok(output)
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], PayloadError> {
        self.take(length)
    }

    fn skip(&mut self, length: usize) -> Result<(), PayloadError> {
        let _ = self.take(length)?;
        Ok(())
    }

    fn require_empty(&self) -> Result<(), PayloadError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(PayloadError::TrailingBytes)
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PayloadError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PayloadError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(PayloadError::Truncated);
        }
        let start = self.position;
        self.position = end;
        Ok(&self.bytes[start..end])
    }
}

fn validate_profile(profile: &str) -> Result<(), PayloadError> {
    if profile != R1_PAYLOAD_PROFILE
        || profile.is_empty()
        || profile.len() > MAX_PAYLOAD_PROFILE_BYTES
        || !profile.is_ascii()
        || profile
            .bytes()
            .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
    {
        return Err(PayloadError::InvalidManifest("payload profile"));
    }
    Ok(())
}

fn validate_lengths(plaintext_length: usize, stored_length: usize) -> Result<(), PayloadError> {
    if plaintext_length > MAX_PAYLOAD_BYTES || stored_length > MAX_PAYLOAD_BYTES {
        return Err(PayloadError::LengthMismatch {
            expected: MAX_PAYLOAD_BYTES,
            actual: plaintext_length.max(stored_length),
        });
    }
    Ok(())
}

fn target_id(target: SupportedTarget) -> u8 {
    match target {
        SupportedTarget::WindowsX64Gnu => 1,
        SupportedTarget::LinuxX64Gnu217 => 2,
    }
}

fn target_from_id(value: u8) -> Result<SupportedTarget, PayloadError> {
    match value {
        1 => Ok(SupportedTarget::WindowsX64Gnu),
        2 => Ok(SupportedTarget::LinuxX64Gnu217),
        _ => Err(PayloadError::InvalidManifest("target")),
    }
}

fn append_bounded(
    output: &mut SensitiveBytes,
    bytes: &[u8],
    expected_length: usize,
) -> Result<(), DecompressError> {
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or(DecompressError::LengthOverflow)?;
    if next > expected_length || next > MAX_PAYLOAD_BYTES {
        return Err(DecompressError::LengthMismatch {
            expected: expected_length,
            actual: next,
        });
    }
    output.as_mut_vec().extend_from_slice(bytes);
    Ok(())
}

fn append_repeat(
    output: &mut SensitiveBytes,
    byte: u8,
    count: usize,
    expected_length: usize,
) -> Result<(), DecompressError> {
    let next = output
        .len()
        .checked_add(count)
        .ok_or(DecompressError::LengthOverflow)?;
    if next > expected_length || next > MAX_PAYLOAD_BYTES {
        return Err(DecompressError::LengthMismatch {
            expected: expected_length,
            actual: next,
        });
    }
    output.as_mut_vec().resize(next, byte);
    Ok(())
}

fn xxhash32(bytes: &[u8]) -> u32 {
    const PRIME1: u32 = 2_654_435_761;
    const PRIME2: u32 = 2_246_822_519;
    const PRIME3: u32 = 3_266_489_917;
    const PRIME4: u32 = 668_265_263;
    const PRIME5: u32 = 374_761_393;
    let mut position = 0usize;
    let mut hash;
    if bytes.len() >= 16 {
        let mut v1 = PRIME1.wrapping_add(PRIME2);
        let mut v2 = PRIME2;
        let mut v3 = 0u32;
        let mut v4 = 0u32.wrapping_sub(PRIME1);
        while position + 16 <= bytes.len() {
            v1 = round(v1, read_u32_le(bytes, position));
            v2 = round(v2, read_u32_le(bytes, position + 4));
            v3 = round(v3, read_u32_le(bytes, position + 8));
            v4 = round(v4, read_u32_le(bytes, position + 12));
            position += 16;
        }
        hash = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        hash = merge_round(hash, v1);
        hash = merge_round(hash, v2);
        hash = merge_round(hash, v3);
        hash = merge_round(hash, v4);
    } else {
        hash = PRIME5;
    }
    hash = hash.wrapping_add(bytes.len() as u32);
    while position + 4 <= bytes.len() {
        hash = hash
            .wrapping_add(read_u32_le(bytes, position).wrapping_mul(PRIME3))
            .rotate_left(17)
            .wrapping_mul(PRIME4);
        position += 4;
    }
    while position < bytes.len() {
        hash = hash
            .wrapping_add(u32::from(bytes[position]).wrapping_mul(PRIME5))
            .rotate_left(11)
            .wrapping_mul(PRIME1);
        position += 1;
    }
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(PRIME2);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(PRIME3);
    hash ^ (hash >> 16)
}

fn round(accumulator: u32, input: u32) -> u32 {
    accumulator
        .wrapping_add(input.wrapping_mul(2_654_435_761))
        .rotate_left(13)
        .wrapping_mul(2_246_822_519)
}

fn merge_round(accumulator: u32, value: u32) -> u32 {
    accumulator ^ round(0, value).wrapping_mul(2_654_435_761)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
