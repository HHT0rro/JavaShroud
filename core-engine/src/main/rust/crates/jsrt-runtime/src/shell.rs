use jsrt_crypto::Digest;
use jsrt_shell::{LoadedArtifact, LoaderError, SupportedTarget};
use std::fmt;

/// A validated native shell image and its final binding identity. The shell
/// loader receives this typed result instead of re-parsing untrusted image
/// headers or accepting a platform fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellArtifact {
    target: SupportedTarget,
    name: String,
    digest: Digest,
    artifact: LoadedArtifact,
}

impl ShellArtifact {
    pub fn validate(target: SupportedTarget, name: &str, bytes: &[u8]) -> Result<Self, ShellError> {
        let artifact = jsrt_shell::validate_artifact(target, name, bytes)?;
        Ok(Self {
            target,
            name: name.to_owned(),
            digest: jsrt_crypto::sha256(artifact.bytes()),
            artifact,
        })
    }

    pub const fn target(&self) -> SupportedTarget {
        self.target
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn bytes(&self) -> &[u8] {
        self.artifact.bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellBinding {
    target: SupportedTarget,
    artifact_digest: Digest,
}

impl ShellBinding {
    pub fn from_artifact(artifact: &ShellArtifact) -> Self {
        Self {
            target: artifact.target,
            artifact_digest: artifact.digest,
        }
    }

    pub const fn target(&self) -> SupportedTarget {
        self.target
    }

    pub const fn artifact_digest(&self) -> &Digest {
        &self.artifact_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShellError {
    Loader(LoaderError),
}

impl fmt::Display for ShellError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loader(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ShellError {}

impl From<LoaderError> for ShellError {
    fn from(error: LoaderError) -> Self {
        Self::Loader(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn shell_binding_is_derived_only_after_image_validation() {
        let artifact =
            ShellArtifact::validate(SupportedTarget::WindowsX64Gnu, "runtime.dll", &pe_x64())
                .expect("artifact");
        let binding = ShellBinding::from_artifact(&artifact);
        assert_eq!(binding.target(), SupportedTarget::WindowsX64Gnu);
        assert_eq!(binding.artifact_digest(), artifact.digest());
    }

    #[test]
    fn shell_rejects_retired_platform_and_legacy_names() {
        assert!(ShellArtifact::validate(
            SupportedTarget::WindowsX64Gnu,
            "runtime.dylib",
            &pe_x64(),
        )
        .is_err());
        assert!(ShellArtifact::validate(
            SupportedTarget::WindowsX64Gnu,
            "legacy-zig.dll",
            &pe_x64(),
        )
        .is_err());
    }
}
