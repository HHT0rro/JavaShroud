#![forbid(unsafe_code)]

use std::fmt;

pub const WINDOWS_X64_GNU: &str = "x86_64-pc-windows-gnu";
pub const LINUX_X64_GNU_217: &str = "x86_64-unknown-linux-gnu.2.17";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SupportedTarget {
    WindowsX64Gnu,
    LinuxX64Gnu217,
}

impl SupportedTarget {
    pub const fn triple(self) -> &'static str {
        match self {
            Self::WindowsX64Gnu => WINDOWS_X64_GNU,
            Self::LinuxX64Gnu217 => LINUX_X64_GNU_217,
        }
    }

    pub const fn artifact_suffix(self) -> &'static str {
        match self {
            Self::WindowsX64Gnu => ".dll",
            Self::LinuxX64Gnu217 => ".so",
        }
    }

    pub fn parse(triple: &str) -> Result<Self, PlatformError> {
        match triple {
            WINDOWS_X64_GNU => Ok(Self::WindowsX64Gnu),
            LINUX_X64_GNU_217 => Ok(Self::LinuxX64Gnu217),
            _ => Err(PlatformError::UnsupportedTarget(triple.to_owned())),
        }
    }

    pub fn compiled_host() -> Result<Self, PlatformError> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "gnu"))]
        {
            return Ok(Self::WindowsX64Gnu);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            return Ok(Self::LinuxX64Gnu217);
        }
        #[allow(unreachable_code)]
        Err(PlatformError::UnsupportedHost {
            target: option_env!("TARGET").unwrap_or("unknown"),
        })
    }

    pub const fn all() -> [Self; 2] {
        [Self::WindowsX64Gnu, Self::LinuxX64Gnu217]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformError {
    UnsupportedTarget(String),
    UnsupportedHost { target: &'static str },
    UnsupportedArtifact { reason: &'static str },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTarget(target) => {
                write!(formatter, "unsupported runtime target: {target}")
            }
            Self::UnsupportedHost { target } => {
                write!(formatter, "unsupported runtime host: {target}")
            }
            Self::UnsupportedArtifact { reason } => {
                write!(formatter, "unsupported runtime artifact: {reason}")
            }
        }
    }
}

impl std::error::Error for PlatformError {}

pub fn is_supported_target(triple: &str) -> bool {
    SupportedTarget::parse(triple).is_ok()
}

pub fn reject_legacy_or_macos_name(name: &str) -> Result<(), PlatformError> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("macos")
        || lower.contains("darwin")
        || lower.ends_with(".dylib")
        || lower.contains("macho")
        || lower.contains("mach-o")
    {
        return Err(PlatformError::UnsupportedArtifact {
            reason: "macOS, Mach-O, and .dylib are not supported",
        });
    }
    if lower.contains("zig") || lower.ends_with(".c") {
        return Err(PlatformError::UnsupportedArtifact {
            reason: "legacy C/Zig runtime paths are retired",
        });
    }
    if lower.contains("://")
        || lower.starts_with("network:")
        || lower.split(['/', '\\']).any(|segment| {
            matches!(
                segment,
                "cache" | "caches" | "temp" | "tmp" | "build" | "builds"
            )
        })
    {
        return Err(PlatformError::UnsupportedArtifact {
            reason: "network, cache, temp, and build paths are not runtime inputs",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_r1_targets_are_accepted() {
        assert_eq!(
            SupportedTarget::parse(WINDOWS_X64_GNU),
            Ok(SupportedTarget::WindowsX64Gnu)
        );
        assert_eq!(
            SupportedTarget::parse(LINUX_X64_GNU_217),
            Ok(SupportedTarget::LinuxX64Gnu217)
        );
        for retired in [
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ] {
            assert!(
                !is_supported_target(retired),
                "retired target accepted: {retired}"
            );
        }
    }

    #[test]
    fn retired_artifact_names_fail_closed() {
        assert!(reject_legacy_or_macos_name("libjsrt.dylib").is_err());
        assert!(reject_legacy_or_macos_name("jsrt-macho").is_err());
        assert!(reject_legacy_or_macos_name("legacy-zig-runtime").is_err());
        for path in [
            "network://runtime.dll",
            "META-INF/cache/runtime.dll",
            "META-INF/temp/runtime.dll",
            "META-INF/build/runtime.dll",
        ] {
            assert!(
                reject_legacy_or_macos_name(path).is_err(),
                "accepted path: {path}"
            );
        }
        assert!(reject_legacy_or_macos_name("META-INF/jsrt/runtime.dll").is_ok());
        assert!(reject_legacy_or_macos_name("runtime.dll").is_ok());
    }
}
