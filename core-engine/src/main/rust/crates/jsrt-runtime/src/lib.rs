#![forbid(unsafe_code)]

pub mod lifecycle;
pub mod page;
pub mod router;
pub mod shell;
pub mod vm;

pub use jsrt_shell::SupportedTarget;
pub use lifecycle::{
    ArenaError, ArtifactIndex, ArtifactIndexEntry, Capabilities, CapabilitySet, DecoderContext,
    FixedCache, GenerationState, LifecycleError, RuntimeGeneration, RuntimeGenerationConfig,
    RuntimeLease, RuntimeLimits, RuntimeSlot, SensitiveArena, SensitiveBytes, ThreadRuntimeContext,
    VmFrame, VmFrameArena, WipedBytes, MAX_ARTIFACT_ENTRIES, MAX_ARTIFACT_NAME_SIZE,
    MAX_CACHE_ENTRIES, MAX_CACHE_VALUE_SIZE, MAX_DECODER_WORKSPACE_SIZE, MAX_SENSITIVE_ARENA_SIZE,
    MAX_VM_FRAMES, MAX_VM_FRAME_SIZE,
};
pub use page::{CallSiteProof, PageError, PageHandle, PageKind, PageRequest};
pub use router::{OpenedPage, RouterError, TypedPageRouter};
pub use shell::{ShellArtifact, ShellBinding, ShellError};
pub use vm::{VmBoundary, VmError, VmResult};

use jsrt_crypto::{Binding, BindingError, Digest, RuntimeBindingDigest};
use jsrt_page::{EnvelopeFrame, ProtocolError, RuntimeEnvelope};
use jsrt_shell::{validate_artifact, LoadedArtifact, LoaderError, PlatformError};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Binding(BindingError),
    Platform(PlatformError),
    Protocol(ProtocolError),
    Loader(LoaderError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(error) => error.fmt(formatter),
            Self::Platform(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
            Self::Loader(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<BindingError> for RuntimeError {
    fn from(error: BindingError) -> Self {
        Self::Binding(error)
    }
}

impl From<PlatformError> for RuntimeError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<ProtocolError> for RuntimeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<LoaderError> for RuntimeError {
    fn from(error: LoaderError) -> Self {
        Self::Loader(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Runtime {
    target: SupportedTarget,
    binding: Binding,
}

impl Runtime {
    pub fn new(target: SupportedTarget, binding: &[u8]) -> Result<Self, RuntimeError> {
        Ok(Self {
            target,
            binding: Binding::from_slice(binding)?,
        })
    }

    pub fn for_target_triple(target: &str, binding: &[u8]) -> Result<Self, RuntimeError> {
        Self::new(SupportedTarget::parse(target)?, binding)
    }

    pub fn for_compiled_host(binding: &[u8]) -> Result<Self, RuntimeError> {
        Self::new(SupportedTarget::compiled_host()?, binding)
    }

    pub fn target(&self) -> SupportedTarget {
        self.target
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    pub fn binding_digest(&self) -> RuntimeBindingDigest {
        RuntimeBindingDigest::compute(&self.binding)
    }

    pub fn binding_digest_bytes(&self) -> Digest {
        *self.binding_digest().as_digest()
    }

    /// This is the only runtime entry into a wire payload.  It delegates to
    /// the protocol's authenticate-before-parse operation and returns no bytes
    /// on any authentication or framing failure.
    pub fn authenticate_frame(&self, frame: &[u8]) -> Result<EnvelopeFrame, RuntimeError> {
        Ok(RuntimeEnvelope::open(&self.binding, frame)?)
    }

    pub fn open_payload(&self, frame: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        Ok(self.authenticate_frame(frame)?.into_payload())
    }

    pub fn validate_artifact(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<LoadedArtifact, RuntimeError> {
        Ok(validate_artifact(self.target, name, bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsrt_page::RuntimeEnvelope;
    use jsrt_shell::{SupportedTarget, LINUX_X64_GNU_217};

    #[test]
    fn runtime_requires_supported_target_and_authenticates_before_opening() {
        let runtime = Runtime::new(SupportedTarget::WindowsX64Gnu, b"binding").expect("runtime");
        let frame = RuntimeEnvelope::encode(runtime.binding(), b"opaque payload").expect("frame");
        assert_eq!(
            runtime.open_payload(&frame).expect("payload"),
            b"opaque payload"
        );

        let mut tampered = frame;
        tampered[0] = b'X';
        assert!(matches!(
            runtime.open_payload(&tampered),
            Err(RuntimeError::Protocol(ProtocolError::InvalidMagic))
        ));
        assert!(Runtime::for_target_triple("x86_64-apple-darwin", b"binding").is_err());
    }

    #[test]
    fn exact_linux_target_is_distinct_from_generic_linux() {
        assert!(Runtime::for_target_triple(LINUX_X64_GNU_217, b"binding").is_ok());
        assert!(Runtime::for_target_triple("x86_64-unknown-linux-gnu", b"binding").is_err());
    }
}
