#![forbid(unsafe_code)]

mod elf;
mod loader;
mod payload;
mod pe;
mod plan;
mod platform;

use jsrt_crypto::sha256;
use std::fmt;

pub use elf::{Elf64Image, Elf64Segment, ElfDynamicEntry};
pub use loader::{detect_format, validate_artifact, ArtifactFormat, LoadedArtifact, LoaderError};
pub use payload::{
    Compression, DecompressError, PayloadDecompressor, PayloadEnvelope, PayloadError,
    PayloadManifest, R1Decompressor, SensitiveBytes, R1_PAYLOAD_PROFILE,
};
pub use pe::{Pe64Image, PeDataDirectory, PeSection};
pub use plan::{
    Export, ImageFormat, Import, ImportSymbol, InitPlan, ManualMapPlan, MapBackend,
    MapExecutionError, MapRegion, MemoryProtection, Relocation, RelocationKind, TlsPlan,
};
pub use platform::{
    is_supported_target, reject_legacy_or_macos_name, PlatformError, SupportedTarget,
    LINUX_X64_GNU_217, WINDOWS_X64_GNU,
};

pub const MAX_ARTIFACT_SIZE: usize = 256 * 1024 * 1024;
pub const MAX_IMAGE_SIZE: u64 = 256 * 1024 * 1024;
pub const MAX_SECTIONS: usize = 96;
pub const MAX_SEGMENTS: usize = 128;
pub const MAX_IMPORTS: usize = 16 * 1024;
pub const MAX_EXPORTS: usize = 16 * 1024;
pub const MAX_RELOCATIONS: usize = 1_000_000;
pub const MAX_TLS_CALLBACKS: usize = 128;
pub const MAX_INIT_FUNCTIONS: usize = 4096;
pub const MAX_DYNAMIC_ENTRIES: usize = 4096;
pub const MAX_STRING_BYTES: usize = 4096;
pub const PAGE_SIZE: u64 = 4096;

pub const R1_REQUIRED_EXPORTS: [&str; 4] = [
    "JNI_OnLoad",
    "JNI_OnUnload",
    "jsrt_r1_runtime_binding_digest",
    "jsrt_r1_open_frame",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    start: u64,
    end: u64,
}

impl AddressRange {
    pub const fn new(start: u64, end: u64) -> Result<Self, ParseError> {
        if start >= end {
            return Err(ParseError::Invalid("empty address range"));
        }
        Ok(Self { start, end })
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    pub const fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }

    pub const fn contains_range(self, start: u64, end: u64) -> bool {
        start >= self.start && start <= end && end <= self.end
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    Truncated {
        offset: u64,
        requested: u64,
        remaining: u64,
    },
    Invalid(&'static str),
    Unsupported(&'static str),
    OutOfBounds(&'static str),
    Overflow,
    LimitExceeded(&'static str),
    WriteExecute,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                offset,
                requested,
                remaining,
            } => write!(
                formatter,
                "image truncated at {offset}: requested {requested} bytes, {remaining} remain"
            ),
            Self::Invalid(reason) => write!(formatter, "invalid image: {reason}"),
            Self::Unsupported(reason) => write!(formatter, "unsupported image feature: {reason}"),
            Self::OutOfBounds(reason) => {
                write!(formatter, "image range is out of bounds: {reason}")
            }
            Self::Overflow => formatter.write_str("image arithmetic overflow"),
            Self::LimitExceeded(reason) => write!(formatter, "image limit exceeded: {reason}"),
            Self::WriteExecute => formatter.write_str("writable and executable image range"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BinaryReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BinaryReader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn read_u16_le(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_le_bytes(self.read_fixed()?))
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_le_bytes(self.read_fixed()?))
    }

    pub(crate) fn read_u64_le(&mut self) -> Result<u64, ParseError> {
        Ok(u64::from_le_bytes(self.read_fixed()?))
    }

    pub(crate) fn read_i64_le(&mut self) -> Result<i64, ParseError> {
        Ok(i64::from_le_bytes(self.read_fixed()?))
    }

    pub(crate) fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        self.take(length)
    }

    pub(crate) fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let bytes = self.take(N)?;
        let mut output = [0u8; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ParseError::Overflow)?;
        if end > self.bytes.len() {
            return Err(ParseError::Truncated {
                offset: self.position as u64,
                requested: length as u64,
                remaining: self.bytes.len().saturating_sub(self.position) as u64,
            });
        }
        let start = self.position;
        self.position = end;
        Ok(&self.bytes[start..end])
    }
}

pub(crate) fn checked_range(
    start: u64,
    length: u64,
    limit: u64,
) -> Result<AddressRange, ParseError> {
    let end = start.checked_add(length).ok_or(ParseError::Overflow)?;
    if end > limit {
        return Err(ParseError::OutOfBounds("declared range exceeds image"));
    }
    AddressRange::new(start, end)
}

pub(crate) fn checked_usize(value: u64) -> Result<usize, ParseError> {
    usize::try_from(value).map_err(|_| ParseError::Overflow)
}

pub(crate) fn is_power_of_two(value: u64) -> bool {
    value != 0 && (value & (value - 1)) == 0
}

pub(crate) fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

pub(crate) fn align_up(value: u64, alignment: u64) -> Result<u64, ParseError> {
    let adjusted = value
        .checked_add(alignment - 1)
        .ok_or(ParseError::Overflow)?;
    Ok(adjusted & !(alignment - 1))
}

#[derive(Debug)]
pub struct ShellArtifact {
    target: SupportedTarget,
    name: String,
    format: ImageFormat,
    digest: [u8; 32],
    bytes: SensitiveBytes,
    plan: ManualMapPlan,
}

impl ShellArtifact {
    pub fn validate(target: SupportedTarget, name: &str, bytes: &[u8]) -> Result<Self, ShellError> {
        if bytes.is_empty() {
            return Err(ShellError::EmptyArtifact);
        }
        if bytes.len() > MAX_ARTIFACT_SIZE {
            return Err(ShellError::ArtifactTooLarge {
                size: bytes.len(),
                max: MAX_ARTIFACT_SIZE,
            });
        }
        reject_legacy_or_macos_name(name)?;
        match target {
            SupportedTarget::WindowsX64Gnu => {
                if !name.to_ascii_lowercase().ends_with(".dll") {
                    return Err(ShellError::TargetFormatMismatch);
                }
                let image = Pe64Image::parse(bytes)?;
                let plan = image.map_plan()?;
                plan.require_r1_exports()?;
                let digest = sha256(bytes).into_bytes();
                Ok(Self {
                    target,
                    name: name.to_owned(),
                    format: ImageFormat::Pe64,
                    digest,
                    bytes: SensitiveBytes::new(bytes.to_vec()),
                    plan,
                })
            }
            SupportedTarget::LinuxX64Gnu217 => {
                if !name.to_ascii_lowercase().ends_with(".so") {
                    return Err(ShellError::TargetFormatMismatch);
                }
                let image = Elf64Image::parse(bytes)?;
                let plan = image.map_plan()?;
                plan.require_r1_exports()?;
                let digest = sha256(bytes).into_bytes();
                Ok(Self {
                    target,
                    name: name.to_owned(),
                    format: ImageFormat::Elf64,
                    digest,
                    bytes: SensitiveBytes::new(bytes.to_vec()),
                    plan,
                })
            }
        }
    }

    pub const fn target(&self) -> SupportedTarget {
        self.target
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn format(&self) -> ImageFormat {
        self.format
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub const fn plan(&self) -> &ManualMapPlan {
        &self.plan
    }

    pub fn execute<B: MapBackend>(
        &self,
        backend: &mut B,
    ) -> Result<B::Mapping, MapExecutionError<B::Error>> {
        self.plan.execute(self.bytes(), backend)
    }
}

pub fn parse_r1_plan(
    target: SupportedTarget,
    name: &str,
    bytes: &[u8],
) -> Result<ManualMapPlan, ShellError> {
    if bytes.is_empty() {
        return Err(ShellError::EmptyArtifact);
    }
    if bytes.len() > MAX_ARTIFACT_SIZE {
        return Err(ShellError::ArtifactTooLarge {
            size: bytes.len(),
            max: MAX_ARTIFACT_SIZE,
        });
    }
    reject_legacy_or_macos_name(name)?;
    match target {
        SupportedTarget::WindowsX64Gnu => {
            if !name.to_ascii_lowercase().ends_with(".dll") {
                return Err(ShellError::TargetFormatMismatch);
            }
            let plan = Pe64Image::parse(bytes)?.map_plan()?;
            plan.require_r1_exports()?;
            Ok(plan)
        }
        SupportedTarget::LinuxX64Gnu217 => {
            if !name.to_ascii_lowercase().ends_with(".so") {
                return Err(ShellError::TargetFormatMismatch);
            }
            let plan = Elf64Image::parse(bytes)?.map_plan()?;
            plan.require_r1_exports()?;
            Ok(plan)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShellError {
    Platform(PlatformError),
    EmptyArtifact,
    ArtifactTooLarge { size: usize, max: usize },
    TargetFormatMismatch,
    UnsupportedFormat,
    Parse(ParseError),
    Payload(PayloadError),
    MissingRequiredExport(&'static str),
    ForwardedRequiredExport(String),
}

impl fmt::Display for ShellError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => error.fmt(formatter),
            Self::EmptyArtifact => formatter.write_str("runtime shell artifact is empty"),
            Self::ArtifactTooLarge { size, max } => {
                write!(
                    formatter,
                    "runtime shell artifact is too large: {size} > {max}"
                )
            }
            Self::TargetFormatMismatch => {
                formatter.write_str("runtime shell name and target do not match")
            }
            Self::UnsupportedFormat => formatter.write_str("runtime shell format is unsupported"),
            Self::Parse(error) => error.fmt(formatter),
            Self::Payload(error) => error.fmt(formatter),
            Self::MissingRequiredExport(name) => {
                write!(formatter, "runtime shell is missing required export {name}")
            }
            Self::ForwardedRequiredExport(name) => {
                write!(
                    formatter,
                    "runtime shell required export is forwarded: {name}"
                )
            }
        }
    }
}

impl std::error::Error for ShellError {}

impl From<PlatformError> for ShellError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<ParseError> for ShellError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<PayloadError> for ShellError {
    fn from(error: PayloadError) -> Self {
        Self::Payload(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_names_are_strict_and_empty_images_fail() {
        assert!(matches!(
            ShellArtifact::validate(SupportedTarget::WindowsX64Gnu, "runtime.so", b"MZ"),
            Err(ShellError::TargetFormatMismatch)
        ));
        assert!(matches!(
            ShellArtifact::validate(SupportedTarget::WindowsX64Gnu, "runtime.dll", &[]),
            Err(ShellError::EmptyArtifact)
        ));
        assert!(
            ShellArtifact::validate(SupportedTarget::WindowsX64Gnu, "runtime.dylib", b"MZ")
                .is_err()
        );
    }
}
