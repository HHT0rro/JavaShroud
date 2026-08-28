#![forbid(unsafe_code)]

use crate::platform::{reject_legacy_or_macos_name, PlatformError, SupportedTarget};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactFormat {
    WindowsPeGnu,
    LinuxElfGnu217,
    MachO,
    Unknown,
}

impl ArtifactFormat {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::WindowsPeGnu | Self::LinuxElfGnu217)
    }
}

pub fn detect_format(bytes: &[u8]) -> ArtifactFormat {
    if is_x64_pe(bytes) {
        return ArtifactFormat::WindowsPeGnu;
    }
    if bytes.len() >= 20 && bytes[..4] == *b"\x7fELF" {
        if is_x64_elf_shared(bytes) {
            return ArtifactFormat::LinuxElfGnu217;
        }
        return ArtifactFormat::Unknown;
    }
    if bytes.len() >= 4
        && matches!(
            bytes[..4],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
    {
        return ArtifactFormat::MachO;
    }
    ArtifactFormat::Unknown
}

fn is_x64_elf_shared(bytes: &[u8]) -> bool {
    bytes.len() >= 20
        && bytes[4] == 2
        && bytes[5] == 1
        && bytes[6] == 1
        && u16::from_le_bytes([bytes[16], bytes[17]]) == 3
        && u16::from_le_bytes([bytes[18], bytes[19]]) == 0x3e
}

fn is_x64_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || bytes[..2] != *b"MZ" {
        return false;
    }
    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let header_end = match pe_offset.checked_add(26) {
        Some(end) => end,
        None => return false,
    };
    if header_end > bytes.len() || bytes[pe_offset..pe_offset + 4] != *b"PE\0\0" {
        return false;
    }
    let machine = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);
    let optional_magic = u16::from_le_bytes([bytes[pe_offset + 24], bytes[pe_offset + 25]]);
    machine == 0x8664 && optional_magic == 0x20b
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedArtifact {
    target: SupportedTarget,
    format: ArtifactFormat,
    bytes: Vec<u8>,
}

impl LoadedArtifact {
    pub fn target(&self) -> SupportedTarget {
        self.target
    }

    pub fn format(&self) -> ArtifactFormat {
        self.format
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for LoadedArtifact {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoaderError {
    Platform(PlatformError),
    EmptyArtifact,
    InvalidName,
    UnsupportedFormat(ArtifactFormat),
    TargetFormatMismatch {
        target: SupportedTarget,
        format: ArtifactFormat,
    },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => error.fmt(formatter),
            Self::EmptyArtifact => formatter.write_str("runtime artifact is empty"),
            Self::InvalidName => {
                formatter.write_str("runtime artifact name is invalid for the current format")
            }
            Self::UnsupportedFormat(format) => {
                write!(formatter, "unsupported runtime artifact format: {format:?}")
            }
            Self::TargetFormatMismatch { target, format } => {
                write!(
                    formatter,
                    "artifact format {format:?} does not match target {}",
                    target.triple()
                )
            }
        }
    }
}

impl std::error::Error for LoaderError {}

impl From<PlatformError> for LoaderError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

/// Validate and retain an artifact without ever entering a legacy C/Zig or
/// dynamic loader path.  Loading/execution of an accepted image is deliberately
/// owned by the later target-specific FFI integration.
pub fn validate_artifact(
    target: SupportedTarget,
    name: &str,
    bytes: &[u8],
) -> Result<LoadedArtifact, LoaderError> {
    if bytes.is_empty() {
        return Err(LoaderError::EmptyArtifact);
    }
    reject_legacy_or_macos_name(name)?;
    let lower_name = name.to_ascii_lowercase();
    let format = detect_format(bytes);
    if !format.is_supported() {
        return Err(LoaderError::UnsupportedFormat(format));
    }
    let name_matches = match target {
        SupportedTarget::WindowsX64Gnu => {
            lower_name.ends_with(".dll") && format == ArtifactFormat::WindowsPeGnu
        }
        SupportedTarget::LinuxX64Gnu217 => {
            lower_name.ends_with(".so") && format == ArtifactFormat::LinuxElfGnu217
        }
    };
    if !name_matches {
        return Err(LoaderError::TargetFormatMismatch { target, format });
    }
    Ok(LoadedArtifact {
        target,
        format,
        bytes: bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_x64() -> Vec<u8> {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes
    }

    fn pe_x64() -> Vec<u8> {
        let mut bytes = vec![0; 0x9a];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes
    }

    #[test]
    fn only_current_target_images_are_retained() {
        let pe =
            validate_artifact(SupportedTarget::WindowsX64Gnu, "jsrt.dll", &pe_x64()).expect("PE");
        assert_eq!(pe.format(), ArtifactFormat::WindowsPeGnu);
        let elf = validate_artifact(SupportedTarget::LinuxX64Gnu217, "libjsrt.so", &elf_x64())
            .expect("ELF");
        assert_eq!(elf.format(), ArtifactFormat::LinuxElfGnu217);
        assert!(
            validate_artifact(SupportedTarget::WindowsX64Gnu, "libjsrt.so", &elf_x64()).is_err()
        );
    }

    #[test]
    fn macho_dylib_and_legacy_paths_are_rejected() {
        assert_eq!(
            detect_format(&[0xfe, 0xed, 0xfa, 0xcf]),
            ArtifactFormat::MachO
        );
        assert!(validate_artifact(SupportedTarget::WindowsX64Gnu, "old.dylib", b"MZ").is_err());
        assert!(
            validate_artifact(SupportedTarget::WindowsX64Gnu, "legacy-zig.dll", b"MZ").is_err()
        );
        assert!(validate_artifact(
            SupportedTarget::WindowsX64Gnu,
            "runtime.dll",
            b"not-an-image"
        )
        .is_err());
    }
}
