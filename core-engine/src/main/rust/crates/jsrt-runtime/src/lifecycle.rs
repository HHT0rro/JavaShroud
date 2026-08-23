use std::fmt;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const MAX_ARTIFACT_ENTRIES: usize = 4096;
pub const MAX_ARTIFACT_NAME_SIZE: usize = 256;
pub const MAX_CACHE_ENTRIES: usize = 256;
pub const MAX_CACHE_VALUE_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_SENSITIVE_ARENA_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_VM_FRAMES: usize = 256;
pub const MAX_VM_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_DECODER_WORKSPACE_SIZE: usize = 4 * 1024 * 1024;

const STATE_ACTIVE: u8 = 1;
const STATE_RETIRING: u8 = 2;
const STATE_UNLOADED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationState {
    Active,
    Retiring,
    Unloaded,
}

impl GenerationState {
    const fn from_raw(value: u8) -> Self {
        match value {
            STATE_ACTIVE => Self::Active,
            STATE_RETIRING => Self::Retiring,
            STATE_UNLOADED => Self::Unloaded,
            _ => Self::Unloaded,
        }
    }
}

impl fmt::Display for GenerationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => formatter.write_str("active"),
            Self::Retiring => formatter.write_str("retiring"),
            Self::Unloaded => formatter.write_str("unloaded"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArenaError {
    CapacityTooLarge { requested: usize, maximum: usize },
    AllocationTooLarge { requested: usize, remaining: usize },
    FrameDepthExceeded { maximum: usize },
    FrameTooLarge { requested: usize, maximum: usize },
}

impl fmt::Display for ArenaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooLarge { requested, maximum } => write!(
                formatter,
                "arena capacity is too large: {requested} > {maximum}"
            ),
            Self::AllocationTooLarge {
                requested,
                remaining,
            } => write!(
                formatter,
                "arena allocation is too large: {requested} requested, {remaining} remain"
            ),
            Self::FrameDepthExceeded { maximum } => {
                write!(formatter, "VM frame depth exceeds bound {maximum}")
            }
            Self::FrameTooLarge { requested, maximum } => {
                write!(formatter, "VM frame is too large: {requested} > {maximum}")
            }
        }
    }
}

impl std::error::Error for ArenaError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    InvalidGenerationId,
    GenerationReplay {
        generation_id: u64,
        last_accepted: u64,
    },
    GenerationState {
        generation_id: u64,
        state: GenerationState,
    },
    NoActiveGeneration,
    UnloadTimeout {
        generation_id: u64,
        active_leases: usize,
    },
    InvalidLimit {
        name: &'static str,
        value: usize,
        maximum: usize,
    },
    InvalidArtifactName,
    InvalidDigestLength {
        size: usize,
    },
    DuplicateArtifact(String),
    CacheFull {
        capacity: usize,
    },
    CacheValueTooLarge {
        size: usize,
        maximum: usize,
    },
    Arena(ArenaError),
    Poisoned(&'static str),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGenerationId => formatter.write_str("runtime generation id must be non-zero"),
            Self::GenerationReplay {
                generation_id,
                last_accepted,
            } => write!(
                formatter,
                "runtime generation replay rejected: {generation_id} <= {last_accepted}"
            ),
            Self::GenerationState {
                generation_id,
                state,
            } => write!(
                formatter,
                "runtime generation {generation_id} is not active: {state}"
            ),
            Self::NoActiveGeneration => formatter.write_str("runtime slot has no active generation"),
            Self::UnloadTimeout {
                generation_id,
                active_leases,
            } => write!(
                formatter,
                "runtime generation {generation_id} did not unload within the bound ({active_leases} leases)"
            ),
            Self::InvalidLimit {
                name,
                value,
                maximum,
            } => write!(formatter, "{name} exceeds bound: {value} > {maximum}"),
            Self::InvalidArtifactName => formatter.write_str("runtime artifact name is invalid"),
            Self::InvalidDigestLength { size } => {
                write!(formatter, "runtime artifact digest must be 32 bytes, got {size}")
            }
            Self::DuplicateArtifact(name) => write!(formatter, "duplicate runtime artifact: {name}"),
            Self::CacheFull { capacity } => {
                write!(formatter, "runtime fixed cache is full at {capacity} entries")
            }
            Self::CacheValueTooLarge { size, maximum } => {
                write!(formatter, "runtime cache value is too large: {size} > {maximum}")
            }
            Self::Arena(error) => error.fmt(formatter),
            Self::Poisoned(name) => write!(formatter, "runtime lifecycle lock is poisoned: {name}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

impl From<ArenaError> for LifecycleError {
    fn from(error: ArenaError) -> Self {
        Self::Arena(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Capabilities(u64);

impl Capabilities {
    pub const NONE: Self = Self(0);
    pub const AUTHENTICATED_PAGES: Self = Self(1 << 0);
    pub const VM_EXECUTION: Self = Self(1 << 1);
    pub const NATIVE_SHELL: Self = Self(1 << 2);
    pub const RESOURCE_DECODER: Self = Self(1 << 3);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::NONE
    }
}

pub type CapabilitySet = Capabilities;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLimits {
    pub max_artifact_entries: usize,
    pub max_cache_entries: usize,
    pub max_cache_value_size: usize,
    pub sensitive_arena_size: usize,
    pub max_vm_frames: usize,
    pub max_vm_frame_size: usize,
    pub decoder_workspace_size: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_artifact_entries: 1024,
            max_cache_entries: 64,
            max_cache_value_size: 1024 * 1024,
            sensitive_arena_size: 1024 * 1024,
            max_vm_frames: 128,
            max_vm_frame_size: 1024 * 1024,
            decoder_workspace_size: 1024 * 1024,
        }
    }
}

impl RuntimeLimits {
    pub fn validate(self) -> Result<Self, LifecycleError> {
        check_limit(
            "max_artifact_entries",
            self.max_artifact_entries,
            MAX_ARTIFACT_ENTRIES,
        )?;
        check_limit(
            "max_cache_entries",
            self.max_cache_entries,
            MAX_CACHE_ENTRIES,
        )?;
        check_limit(
            "max_cache_value_size",
            self.max_cache_value_size,
            MAX_CACHE_VALUE_SIZE,
        )?;
        check_limit(
            "sensitive_arena_size",
            self.sensitive_arena_size,
            MAX_SENSITIVE_ARENA_SIZE,
        )?;
        check_limit("max_vm_frames", self.max_vm_frames, MAX_VM_FRAMES)?;
        check_limit(
            "max_vm_frame_size",
            self.max_vm_frame_size,
            MAX_VM_FRAME_SIZE,
        )?;
        check_limit(
            "decoder_workspace_size",
            self.decoder_workspace_size,
            MAX_DECODER_WORKSPACE_SIZE,
        )?;
        Ok(self)
    }
}

fn check_limit(name: &'static str, value: usize, maximum: usize) -> Result<(), LifecycleError> {
    if value > maximum {
        Err(LifecycleError::InvalidLimit {
            name,
            value,
            maximum,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactIndexEntry {
    name: String,
    digest: [u8; 32],
    size: usize,
}

impl ArtifactIndexEntry {
    pub fn new(
        name: impl Into<String>,
        digest: [u8; 32],
        size: usize,
    ) -> Result<Self, LifecycleError> {
        let name = name.into();
        validate_artifact_name(&name)?;
        Ok(Self { name, digest, size })
    }

    pub fn from_bytes(
        name: impl Into<String>,
        digest: &[u8],
        size: usize,
    ) -> Result<Self, LifecycleError> {
        if digest.len() != 32 {
            return Err(LifecycleError::InvalidDigestLength { size: digest.len() });
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(digest);
        Self::new(name, value, size)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub const fn size(&self) -> usize {
        self.size
    }

    fn wipe(&mut self) {
        self.digest.fill(0);
    }
}

impl fmt::Debug for ArtifactIndexEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactIndexEntry")
            .field("name", &self.name)
            .field("size", &self.size)
            .finish()
    }
}

impl Drop for ArtifactIndexEntry {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactIndex {
    entries: Vec<ArtifactIndexEntry>,
}

impl ArtifactIndex {
    pub fn new(mut entries: Vec<ArtifactIndexEntry>) -> Result<Self, LifecycleError> {
        if entries.len() > MAX_ARTIFACT_ENTRIES {
            return Err(LifecycleError::InvalidLimit {
                name: "artifact entries",
                value: entries.len(),
                maximum: MAX_ARTIFACT_ENTRIES,
            });
        }
        entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        for pair in entries.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(LifecycleError::DuplicateArtifact(pair[0].name.clone()));
            }
        }
        Ok(Self { entries })
    }

    pub fn from_entries(entries: Vec<ArtifactIndexEntry>) -> Result<Self, LifecycleError> {
        Self::new(entries)
    }

    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lookup(&self, name: &str) -> Option<&ArtifactIndexEntry> {
        self.entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.entries[index])
    }

    pub fn contains(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }

    pub fn entries(&self) -> &[ArtifactIndexEntry] {
        &self.entries
    }

    pub fn wipe_and_clear(&mut self) {
        for entry in &mut self.entries {
            entry.wipe();
        }
        self.entries.clear();
    }
}

impl fmt::Debug for ArtifactIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactIndex")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Drop for ArtifactIndex {
    fn drop(&mut self) {
        self.wipe_and_clear();
    }
}

fn validate_artifact_name(name: &str) -> Result<(), LifecycleError> {
    if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_SIZE || name.bytes().any(|byte| byte == 0)
    {
        return Err(LifecycleError::InvalidArtifactName);
    }
    Ok(())
}

#[derive(Clone)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_zeroed(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

impl PartialEq<[u8]> for SensitiveBytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub type WipedBytes = SensitiveBytes;

#[derive(Clone)]
struct CacheEntry {
    key: [u8; 32],
    value: SensitiveBytes,
}

pub struct FixedCache {
    entries: Vec<CacheEntry>,
    capacity: usize,
    max_value_size: usize,
}

impl FixedCache {
    pub fn new(capacity: usize, max_value_size: usize) -> Result<Self, LifecycleError> {
        check_limit("cache capacity", capacity, MAX_CACHE_ENTRIES)?;
        check_limit("cache value size", max_value_size, MAX_CACHE_VALUE_SIZE)?;
        Ok(Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            max_value_size,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.entries.len() == self.capacity
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.entries.iter().any(|entry| &entry.key == key)
    }

    pub fn insert(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), LifecycleError> {
        if value.len() > self.max_value_size {
            return Err(LifecycleError::CacheValueTooLarge {
                size: value.len(),
                maximum: self.max_value_size,
            });
        }
        if let Some(entry) = self.entries.iter_mut().find(|entry| &entry.key == key) {
            entry.value = SensitiveBytes::from_slice(value);
            return Ok(());
        }
        if self.entries.len() >= self.capacity {
            return Err(LifecycleError::CacheFull {
                capacity: self.capacity,
            });
        }
        self.entries.push(CacheEntry {
            key: *key,
            value: SensitiveBytes::from_slice(value),
        });
        Ok(())
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<SensitiveBytes> {
        self.entries
            .iter()
            .find(|entry| &entry.key == key)
            .map(|entry| entry.value.clone())
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> Option<SensitiveBytes> {
        let index = self.entries.iter().position(|entry| &entry.key == key)?;
        let entry = self.entries.swap_remove(index);
        Some(entry.value)
    }

    pub fn clear_and_wipe(&mut self) {
        for entry in &mut self.entries {
            entry.key.fill(0);
            entry.value.as_mut_slice().fill(0);
        }
        self.entries.clear();
    }
}

impl Default for FixedCache {
    fn default() -> Self {
        Self::new(32, 256 * 1024).expect("fixed cache defaults are bounded")
    }
}

impl fmt::Debug for FixedCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedCache")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .field("max_value_size", &self.max_value_size)
            .finish()
    }
}

impl Drop for FixedCache {
    fn drop(&mut self) {
        self.clear_and_wipe();
    }
}

pub struct SensitiveArena {
    storage: Vec<u8>,
    cursor: usize,
}

impl SensitiveArena {
    pub fn new(capacity: usize) -> Result<Self, ArenaError> {
        if capacity > MAX_SENSITIVE_ARENA_SIZE {
            return Err(ArenaError::CapacityTooLarge {
                requested: capacity,
                maximum: MAX_SENSITIVE_ARENA_SIZE,
            });
        }
        Ok(Self {
            storage: vec![0; capacity],
            cursor: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    pub fn used(&self) -> usize {
        self.cursor
    }

    pub fn remaining(&self) -> usize {
        self.storage.len().saturating_sub(self.cursor)
    }

    pub fn allocate(&mut self, size: usize) -> Result<&mut [u8], ArenaError> {
        let remaining = self.remaining();
        if size > remaining {
            return Err(ArenaError::AllocationTooLarge {
                requested: size,
                remaining,
            });
        }
        let start = self.cursor;
        self.cursor += size;
        self.storage[start..self.cursor].fill(0);
        Ok(&mut self.storage[start..self.cursor])
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<&mut [u8], ArenaError> {
        let output = self.allocate(bytes.len())?;
        output.copy_from_slice(bytes);
        Ok(output)
    }

    pub fn reset_and_wipe(&mut self) {
        self.storage.fill(0);
        self.cursor = 0;
    }

    pub fn is_zeroed(&self) -> bool {
        self.cursor == 0 && self.storage.iter().all(|byte| *byte == 0)
    }
}

impl Drop for SensitiveArena {
    fn drop(&mut self) {
        self.reset_and_wipe();
    }
}

pub struct VmFrame {
    bytes: Vec<u8>,
}

impl VmFrame {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn into_sensitive(mut self) -> SensitiveBytes {
        let mut bytes = Vec::new();
        std::mem::swap(&mut bytes, &mut self.bytes);
        SensitiveBytes::new(bytes)
    }
}

impl Drop for VmFrame {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

pub struct VmFrameArena {
    frames: Vec<VmFrame>,
    max_frames: usize,
    max_frame_size: usize,
}

impl VmFrameArena {
    pub fn new(max_frames: usize, max_frame_size: usize) -> Result<Self, ArenaError> {
        if max_frames > MAX_VM_FRAMES {
            return Err(ArenaError::CapacityTooLarge {
                requested: max_frames,
                maximum: MAX_VM_FRAMES,
            });
        }
        if max_frame_size > MAX_VM_FRAME_SIZE {
            return Err(ArenaError::CapacityTooLarge {
                requested: max_frame_size,
                maximum: MAX_VM_FRAME_SIZE,
            });
        }
        Ok(Self {
            frames: Vec::with_capacity(max_frames),
            max_frames,
            max_frame_size,
        })
    }

    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    pub fn max_depth(&self) -> usize {
        self.max_frames
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<&mut [u8], ArenaError> {
        if bytes.len() > self.max_frame_size {
            return Err(ArenaError::FrameTooLarge {
                requested: bytes.len(),
                maximum: self.max_frame_size,
            });
        }
        if self.frames.len() >= self.max_frames {
            return Err(ArenaError::FrameDepthExceeded {
                maximum: self.max_frames,
            });
        }
        self.frames.push(VmFrame {
            bytes: bytes.to_vec(),
        });
        Ok(self
            .frames
            .last_mut()
            .expect("frame was just pushed")
            .as_mut_slice())
    }

    pub fn push_zeroed(&mut self, size: usize) -> Result<&mut [u8], ArenaError> {
        if size > self.max_frame_size {
            return Err(ArenaError::FrameTooLarge {
                requested: size,
                maximum: self.max_frame_size,
            });
        }
        if self.frames.len() >= self.max_frames {
            return Err(ArenaError::FrameDepthExceeded {
                maximum: self.max_frames,
            });
        }
        self.frames.push(VmFrame {
            bytes: vec![0; size],
        });
        Ok(self
            .frames
            .last_mut()
            .expect("frame was just pushed")
            .as_mut_slice())
    }

    pub fn frame(&self, index: usize) -> Option<&[u8]> {
        self.frames.get(index).map(VmFrame::as_slice)
    }

    pub fn pop(&mut self) -> Option<SensitiveBytes> {
        self.frames.pop().map(VmFrame::into_sensitive)
    }

    pub fn reset_and_wipe(&mut self) {
        self.frames.clear();
    }
}

impl Drop for VmFrameArena {
    fn drop(&mut self) {
        self.reset_and_wipe();
    }
}

pub struct DecoderContext {
    workspace: Vec<u8>,
    cursor: usize,
}

impl DecoderContext {
    pub fn new(capacity: usize) -> Result<Self, ArenaError> {
        if capacity > MAX_DECODER_WORKSPACE_SIZE {
            return Err(ArenaError::CapacityTooLarge {
                requested: capacity,
                maximum: MAX_DECODER_WORKSPACE_SIZE,
            });
        }
        Ok(Self {
            workspace: vec![0; capacity],
            cursor: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.workspace.len()
    }

    pub fn used(&self) -> usize {
        self.cursor
    }

    pub fn reserve(&mut self, size: usize) -> Result<&mut [u8], ArenaError> {
        let remaining = self.workspace.len().saturating_sub(self.cursor);
        if size > remaining {
            return Err(ArenaError::AllocationTooLarge {
                requested: size,
                remaining,
            });
        }
        let start = self.cursor;
        self.cursor += size;
        self.workspace[start..self.cursor].fill(0);
        Ok(&mut self.workspace[start..self.cursor])
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<&mut [u8], ArenaError> {
        let output = self.reserve(bytes.len())?;
        output.copy_from_slice(bytes);
        Ok(output)
    }

    pub fn reset_and_wipe(&mut self) {
        self.workspace.fill(0);
        self.cursor = 0;
    }

    pub fn is_zeroed(&self) -> bool {
        self.cursor == 0 && self.workspace.iter().all(|byte| *byte == 0)
    }
}

impl Drop for DecoderContext {
    fn drop(&mut self) {
        self.reset_and_wipe();
    }
}

pub struct ThreadRuntimeContext {
    sensitive: SensitiveArena,
    vm_frames: VmFrameArena,
    decoder: DecoderContext,
}

impl ThreadRuntimeContext {
    pub fn new(limits: RuntimeLimits) -> Result<Self, LifecycleError> {
        let limits = limits.validate()?;
        Ok(Self {
            sensitive: SensitiveArena::new(limits.sensitive_arena_size)?,
            vm_frames: VmFrameArena::new(limits.max_vm_frames, limits.max_vm_frame_size)?,
            decoder: DecoderContext::new(limits.decoder_workspace_size)?,
        })
    }

    pub fn sensitive_arena(&mut self) -> &mut SensitiveArena {
        &mut self.sensitive
    }

    pub fn sensitive_arena_mut(&mut self) -> &mut SensitiveArena {
        &mut self.sensitive
    }

    pub fn vm_frame_arena(&mut self) -> &mut VmFrameArena {
        &mut self.vm_frames
    }

    pub fn vm_frame_arena_mut(&mut self) -> &mut VmFrameArena {
        &mut self.vm_frames
    }

    pub fn decoder_context(&mut self) -> &mut DecoderContext {
        &mut self.decoder
    }

    pub fn decoder_context_mut(&mut self) -> &mut DecoderContext {
        &mut self.decoder
    }

    pub fn reset_and_wipe(&mut self) {
        self.sensitive.reset_and_wipe();
        self.vm_frames.reset_and_wipe();
        self.decoder.reset_and_wipe();
    }
}

impl Drop for ThreadRuntimeContext {
    fn drop(&mut self) {
        self.reset_and_wipe();
    }
}

#[derive(Clone)]
pub struct RuntimeGenerationConfig {
    pub generation_id: u64,
    pub artifact_index: ArtifactIndex,
    pub capabilities: Capabilities,
    pub limits: RuntimeLimits,
}

impl RuntimeGenerationConfig {
    pub fn new(
        generation_id: u64,
        artifact_index: ArtifactIndex,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            generation_id,
            artifact_index,
            capabilities,
            limits: RuntimeLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: RuntimeLimits) -> Self {
        self.limits = limits;
        self
    }
}

struct GenerationResources {
    artifact_index: ArtifactIndex,
    cache: FixedCache,
}

impl GenerationResources {
    fn wipe_and_clear(&mut self) {
        self.cache.clear_and_wipe();
        self.artifact_index.wipe_and_clear();
    }
}

pub struct RuntimeGeneration {
    generation_id: u64,
    state: AtomicU8,
    active_leases: AtomicUsize,
    lifecycle_lock: Mutex<()>,
    lifecycle_changed: Condvar,
    capabilities: Capabilities,
    limits: RuntimeLimits,
    resources: Mutex<GenerationResources>,
}

impl RuntimeGeneration {
    pub fn new(
        generation_id: u64,
        artifact_index: ArtifactIndex,
        capabilities: Capabilities,
    ) -> Result<Arc<Self>, LifecycleError> {
        Self::from_config(RuntimeGenerationConfig::new(
            generation_id,
            artifact_index,
            capabilities,
        ))
    }

    pub fn with_limits(
        generation_id: u64,
        artifact_index: ArtifactIndex,
        capabilities: Capabilities,
        limits: RuntimeLimits,
    ) -> Result<Arc<Self>, LifecycleError> {
        Self::from_config(
            RuntimeGenerationConfig::new(generation_id, artifact_index, capabilities)
                .with_limits(limits),
        )
    }

    pub fn try_new(config: RuntimeGenerationConfig) -> Result<Arc<Self>, LifecycleError> {
        Self::from_config(config)
    }

    pub fn from_config(config: RuntimeGenerationConfig) -> Result<Arc<Self>, LifecycleError> {
        if config.generation_id == 0 {
            return Err(LifecycleError::InvalidGenerationId);
        }
        let limits = config.limits.validate()?;
        let cache = FixedCache::new(limits.max_cache_entries, limits.max_cache_value_size)?;
        Ok(Arc::new(Self {
            generation_id: config.generation_id,
            state: AtomicU8::new(STATE_ACTIVE),
            active_leases: AtomicUsize::new(0),
            lifecycle_lock: Mutex::new(()),
            lifecycle_changed: Condvar::new(),
            capabilities: config.capabilities,
            limits,
            resources: Mutex::new(GenerationResources {
                artifact_index: config.artifact_index,
                cache,
            }),
        }))
    }

    pub const fn generation_id(&self) -> u64 {
        self.generation_id
    }

    pub fn state(&self) -> GenerationState {
        GenerationState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub fn active_leases(&self) -> usize {
        self.active_leases.load(Ordering::Acquire)
    }

    pub const fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    pub const fn limits(&self) -> RuntimeLimits {
        self.limits
    }

    pub fn is_wiped(&self) -> bool {
        self.state() == GenerationState::Unloaded
            && self
                .resources
                .lock()
                .map(|resources| resources.artifact_index.is_empty() && resources.cache.is_empty())
                .unwrap_or(true)
    }

    pub fn artifact_index(&self) -> Result<ArtifactIndex, LifecycleError> {
        self.ensure_accessible()?;
        let resources = self
            .resources
            .lock()
            .map_err(|_| LifecycleError::Poisoned("generation resources"))?;
        Ok(resources.artifact_index.clone())
    }

    pub fn cache_len(&self) -> Result<usize, LifecycleError> {
        self.ensure_accessible()?;
        let resources = self
            .resources
            .lock()
            .map_err(|_| LifecycleError::Poisoned("generation resources"))?;
        Ok(resources.cache.len())
    }

    pub fn cache_insert(&self, key: &[u8; 32], value: &[u8]) -> Result<(), LifecycleError> {
        self.ensure_accessible()?;
        let mut resources = self
            .resources
            .lock()
            .map_err(|_| LifecycleError::Poisoned("generation resources"))?;
        resources.cache.insert(key, value)
    }

    pub fn cache_get(&self, key: &[u8; 32]) -> Result<Option<SensitiveBytes>, LifecycleError> {
        self.ensure_accessible()?;
        let resources = self
            .resources
            .lock()
            .map_err(|_| LifecycleError::Poisoned("generation resources"))?;
        Ok(resources.cache.get(key))
    }

    pub fn thread_context(&self) -> Result<ThreadRuntimeContext, LifecycleError> {
        self.ensure_accessible()?;
        ThreadRuntimeContext::new(self.limits)
    }

    pub fn with_thread_context<T, F>(&self, function: F) -> Result<T, LifecycleError>
    where
        F: FnOnce(&mut ThreadRuntimeContext) -> T,
    {
        let mut context = self.thread_context()?;
        Ok(function(&mut context))
    }

    pub fn begin_retirement(&self) -> Result<(), LifecycleError> {
        match self.state.compare_exchange(
            STATE_ACTIVE,
            STATE_RETIRING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.unload_if_idle()?;
                Ok(())
            }
            Err(STATE_RETIRING) => Ok(()),
            Err(_) => Err(LifecycleError::GenerationState {
                generation_id: self.generation_id,
                state: self.state(),
            }),
        }
    }

    pub fn wait_for_unload(&self, timeout: Duration) -> Result<(), LifecycleError> {
        if self.state() == GenerationState::Unloaded {
            return Ok(());
        }
        if self.state() != GenerationState::Retiring {
            return Err(LifecycleError::GenerationState {
                generation_id: self.generation_id,
                state: self.state(),
            });
        }
        let start = Instant::now();
        let mut guard = self
            .lifecycle_lock
            .lock()
            .map_err(|_| LifecycleError::Poisoned("generation lifecycle"))?;
        loop {
            if self.state() == GenerationState::Unloaded {
                return Ok(());
            }
            let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                return Err(self.unload_timeout());
            };
            if remaining == Duration::ZERO {
                return Err(self.unload_timeout());
            }
            let (next_guard, result) = self
                .lifecycle_changed
                .wait_timeout(guard, remaining)
                .map_err(|_| LifecycleError::Poisoned("generation lifecycle"))?;
            guard = next_guard;
            if result.timed_out() && self.state() != GenerationState::Unloaded {
                return Err(self.unload_timeout());
            }
        }
    }

    pub fn acquire(self: &Arc<Self>) -> Result<RuntimeLease, LifecycleError> {
        if self.state() != GenerationState::Active {
            return Err(LifecycleError::GenerationState {
                generation_id: self.generation_id,
                state: self.state(),
            });
        }
        self.active_leases.fetch_add(1, Ordering::AcqRel);
        if self.state() != GenerationState::Active {
            self.release_lease();
            return Err(LifecycleError::GenerationState {
                generation_id: self.generation_id,
                state: self.state(),
            });
        }
        Ok(RuntimeLease {
            generation: Some(Arc::clone(self)),
        })
    }

    fn release_lease(&self) {
        let mut current = self.active_leases.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return;
            }
            match self.active_leases.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if current == 1 {
                        let _ = self.unload_if_idle();
                    }
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn unload_if_idle(&self) -> Result<(), LifecycleError> {
        if self.active_leases.load(Ordering::Acquire) != 0 {
            return Ok(());
        }
        if self
            .state
            .compare_exchange(
                STATE_RETIRING,
                STATE_UNLOADED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Ok(());
        }
        let mut resources = self
            .resources
            .lock()
            .map_err(|_| LifecycleError::Poisoned("generation resources"))?;
        resources.wipe_and_clear();
        self.lifecycle_changed.notify_all();
        Ok(())
    }

    fn ensure_accessible(&self) -> Result<(), LifecycleError> {
        let state = self.state();
        if state == GenerationState::Unloaded {
            Err(LifecycleError::GenerationState {
                generation_id: self.generation_id,
                state,
            })
        } else {
            Ok(())
        }
    }

    fn unload_timeout(&self) -> LifecycleError {
        LifecycleError::UnloadTimeout {
            generation_id: self.generation_id,
            active_leases: self.active_leases(),
        }
    }
}

impl fmt::Debug for RuntimeGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeGeneration")
            .field("generation_id", &self.generation_id)
            .field("state", &self.state())
            .field("active_leases", &self.active_leases())
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl Drop for RuntimeGeneration {
    fn drop(&mut self) {
        if let Ok(mut resources) = self.resources.lock() {
            resources.wipe_and_clear();
        }
    }
}

pub struct RuntimeLease {
    generation: Option<Arc<RuntimeGeneration>>,
}

impl RuntimeLease {
    pub fn generation_id(&self) -> Result<u64, LifecycleError> {
        Ok(self.generation_ref()?.generation_id())
    }

    pub fn state(&self) -> Result<GenerationState, LifecycleError> {
        Ok(self.generation_ref()?.state())
    }

    pub fn capabilities(&self) -> Result<Capabilities, LifecycleError> {
        Ok(self.generation_ref()?.capabilities())
    }

    pub fn artifact_index(&self) -> Result<ArtifactIndex, LifecycleError> {
        self.generation_ref()?.artifact_index()
    }

    pub fn cache_insert(&self, key: &[u8; 32], value: &[u8]) -> Result<(), LifecycleError> {
        self.generation_ref()?.cache_insert(key, value)
    }

    pub fn cache_get(&self, key: &[u8; 32]) -> Result<Option<SensitiveBytes>, LifecycleError> {
        self.generation_ref()?.cache_get(key)
    }

    pub fn thread_context(&self) -> Result<ThreadRuntimeContext, LifecycleError> {
        self.generation_ref()?.thread_context()
    }

    pub fn with_thread_context<T, F>(&self, function: F) -> Result<T, LifecycleError>
    where
        F: FnOnce(&mut ThreadRuntimeContext) -> T,
    {
        self.generation_ref()?.with_thread_context(function)
    }

    pub fn close(&mut self) {
        if let Some(generation) = self.generation.take() {
            generation.release_lease();
        }
    }

    fn generation_ref(&self) -> Result<&RuntimeGeneration, LifecycleError> {
        self.generation
            .as_deref()
            .ok_or(LifecycleError::GenerationState {
                generation_id: 0,
                state: GenerationState::Unloaded,
            })
    }
}

impl fmt::Debug for RuntimeLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeLease")
            .field(
                "generation_id",
                &self
                    .generation
                    .as_ref()
                    .map(|generation| generation.generation_id),
            )
            .finish()
    }
}

impl Drop for RuntimeLease {
    fn drop(&mut self) {
        self.close();
    }
}

struct SlotState {
    active: Option<Arc<RuntimeGeneration>>,
    retiring: Vec<Arc<RuntimeGeneration>>,
    last_accepted: u64,
}

#[derive(Clone)]
pub struct RuntimeSlot {
    state: Arc<Mutex<SlotState>>,
}

impl RuntimeSlot {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SlotState {
                active: None,
                retiring: Vec::new(),
                last_accepted: 0,
            })),
        }
    }

    pub fn install(&self, generation: Arc<RuntimeGeneration>) -> Result<(), LifecycleError> {
        self.install_inner(generation).map(|_| ())
    }

    pub fn activate(&self, generation: Arc<RuntimeGeneration>) -> Result<(), LifecycleError> {
        self.install(generation)
    }

    pub fn replace(
        &self,
        generation: Arc<RuntimeGeneration>,
        timeout: Duration,
    ) -> Result<(), LifecycleError> {
        let old = self.install_inner(generation)?;
        if let Some(old) = old {
            old.wait_for_unload(timeout)?;
        }
        self.reap_retired();
        Ok(())
    }

    pub fn acquire(&self) -> Result<RuntimeLease, LifecycleError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LifecycleError::Poisoned("runtime slot"))?;
        let generation = state
            .active
            .as_ref()
            .ok_or(LifecycleError::NoActiveGeneration)?;
        generation.acquire()
    }

    pub fn active_generation(&self) -> Result<Arc<RuntimeGeneration>, LifecycleError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LifecycleError::Poisoned("runtime slot"))?;
        state
            .active
            .as_ref()
            .cloned()
            .ok_or(LifecycleError::NoActiveGeneration)
    }

    pub fn active_generation_id(&self) -> Option<u64> {
        self.state.lock().ok().and_then(|state| {
            state
                .active
                .as_ref()
                .map(|generation| generation.generation_id())
        })
    }

    pub fn last_accepted_generation_id(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.last_accepted)
            .unwrap_or(u64::MAX)
    }

    pub fn retiring_count(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.retiring.len())
            .unwrap_or(0)
    }

    pub fn reap_retired(&self) -> usize {
        let Ok(mut state) = self.state.lock() else {
            return 0;
        };
        let before = state.retiring.len();
        state
            .retiring
            .retain(|generation| generation.state() != GenerationState::Unloaded);
        before - state.retiring.len()
    }

    pub fn retire_active(&self, timeout: Duration) -> Result<(), LifecycleError> {
        let generation = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LifecycleError::Poisoned("runtime slot"))?;
            let generation = state
                .active
                .as_ref()
                .cloned()
                .ok_or(LifecycleError::NoActiveGeneration)?;
            generation.begin_retirement()?;
            state.active.take().expect("active generation was present")
        };
        let result = generation.wait_for_unload(timeout);
        self.reap_retired();
        result
    }

    pub fn shutdown(&self, timeout: Duration) -> Result<(), LifecycleError> {
        let generations = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LifecycleError::Poisoned("runtime slot"))?;
            if let Some(active) = state.active.take() {
                active.begin_retirement()?;
                state.retiring.push(active);
            }
            state.retiring.clone()
        };
        let start = Instant::now();
        for generation in generations {
            let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                return Err(generation.unload_timeout());
            };
            generation.wait_for_unload(remaining)?;
        }
        self.reap_retired();
        Ok(())
    }

    fn install_inner(
        &self,
        generation: Arc<RuntimeGeneration>,
    ) -> Result<Option<Arc<RuntimeGeneration>>, LifecycleError> {
        if generation.generation_id() == 0 {
            return Err(LifecycleError::InvalidGenerationId);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LifecycleError::Poisoned("runtime slot"))?;
        if generation.generation_id() <= state.last_accepted {
            return Err(LifecycleError::GenerationReplay {
                generation_id: generation.generation_id(),
                last_accepted: state.last_accepted,
            });
        }
        if generation.state() != GenerationState::Active {
            return Err(LifecycleError::GenerationState {
                generation_id: generation.generation_id(),
                state: generation.state(),
            });
        }
        if let Some(active) = state.active.as_ref() {
            active.begin_retirement()?;
        }
        let old = state.active.replace(generation);
        if let Some(previous) = old.as_ref() {
            state.retiring.push(Arc::clone(previous));
        }
        state.last_accepted = state
            .active
            .as_ref()
            .map(|generation| generation.generation_id())
            .unwrap_or(state.last_accepted);
        Ok(old)
    }
}

impl Default for RuntimeSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RuntimeSlot {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(active) = state.active.take() {
            let _ = active.begin_retirement();
        }
        for generation in &state.retiring {
            let _ = generation.begin_retirement();
        }
        state.retiring.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Barrier};
    use std::thread;

    fn index(names: &[&str]) -> ArtifactIndex {
        ArtifactIndex::new(
            names
                .iter()
                .enumerate()
                .map(|(ordinal, name)| {
                    ArtifactIndexEntry::new(*name, [ordinal as u8 + 1; 32], ordinal + 1)
                        .expect("entry")
                })
                .collect(),
        )
        .expect("index")
    }

    fn generation(id: u64) -> Arc<RuntimeGeneration> {
        RuntimeGeneration::new(
            id,
            index(&["META-INF/jsrt/manifest", "META-INF/jsrt/runtime"]),
            Capabilities::AUTHENTICATED_PAGES.union(Capabilities::VM_EXECUTION),
        )
        .expect("generation")
    }

    #[test]
    fn artifact_index_is_sorted_and_uses_binary_search() {
        let index = index(&["z", "a", "m"]);
        assert_eq!(
            index
                .entries()
                .iter()
                .map(ArtifactIndexEntry::name)
                .collect::<Vec<_>>(),
            vec!["a", "m", "z"]
        );
        assert_eq!(index.lookup("m").expect("m").size(), 3);
        assert!(index.lookup("missing").is_none());
        assert!(matches!(
            ArtifactIndex::new(vec![
                ArtifactIndexEntry::new("same", [1; 32], 1).expect("entry"),
                ArtifactIndexEntry::new("same", [2; 32], 2).expect("entry"),
            ]),
            Err(LifecycleError::DuplicateArtifact(_))
        ));
    }

    #[test]
    fn arenas_wipe_after_success_and_failure_paths() {
        let mut sensitive = SensitiveArena::new(16).expect("arena");
        sensitive.write(b"secret").expect("write");
        assert_eq!(sensitive.used(), 6);
        assert!(matches!(
            sensitive.allocate(11),
            Err(ArenaError::AllocationTooLarge { .. })
        ));
        sensitive.reset_and_wipe();
        assert!(sensitive.is_zeroed());

        let mut frames = VmFrameArena::new(1, 8).expect("frames");
        frames.push(b"frame").expect("frame");
        assert!(matches!(
            frames.push(b"second"),
            Err(ArenaError::FrameDepthExceeded { maximum: 1 })
        ));
        let frame = frames.pop().expect("popped frame");
        assert_eq!(frame.as_slice(), b"frame");
        drop(frame);
        frames.reset_and_wipe();

        let mut decoder = DecoderContext::new(8).expect("decoder");
        decoder.write(b"encoded").expect("decoder write");
        assert!(matches!(
            decoder.reserve(2),
            Err(ArenaError::AllocationTooLarge { .. })
        ));
        decoder.reset_and_wipe();
        assert!(decoder.is_zeroed());
    }

    #[test]
    fn retirement_wait_is_bounded_and_final_release_wipes_generation() {
        let slot = RuntimeSlot::new();
        let first = generation(1);
        slot.install(Arc::clone(&first)).expect("install first");
        let lease = slot.acquire().expect("lease");
        let key = [0x5a; 32];
        lease
            .cache_insert(&key, b"prepared VM frame")
            .expect("cache");

        slot.install(generation(2)).expect("install second");
        assert_eq!(first.state(), GenerationState::Retiring);
        assert!(matches!(
            first.wait_for_unload(Duration::from_millis(1)),
            Err(LifecycleError::UnloadTimeout {
                generation_id: 1,
                active_leases: 1
            })
        ));
        drop(lease);
        first
            .wait_for_unload(Duration::from_secs(1))
            .expect("unload");
        assert!(first.is_wiped());
        assert!(matches!(
            first.cache_get(&key),
            Err(LifecycleError::GenerationState {
                state: GenerationState::Unloaded,
                ..
            })
        ));
    }

    #[test]
    fn replayed_generation_ids_are_rejected_after_retirement() {
        let slot = RuntimeSlot::new();
        slot.install(generation(7)).expect("install");
        slot.install(generation(8)).expect("replace");
        let replay = generation(7);
        assert_eq!(
            slot.install(replay),
            Err(LifecycleError::GenerationReplay {
                generation_id: 7,
                last_accepted: 8,
            })
        );
        assert_eq!(slot.active_generation_id(), Some(8));
    }

    #[test]
    fn multiple_threads_hold_retiring_leases_until_their_work_finishes() {
        let slot = RuntimeSlot::new();
        let first = generation(11);
        slot.install(Arc::clone(&first)).expect("install");
        let lease = slot.acquire().expect("lease");
        let barrier = Arc::new(Barrier::new(2));
        let (release_tx, release_rx) = mpsc::channel();
        let worker = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                release_rx.recv().expect("release signal");
                drop(lease);
            })
        };
        barrier.wait();
        slot.install(generation(12)).expect("replace");
        assert_eq!(first.state(), GenerationState::Retiring);
        assert!(matches!(
            first.wait_for_unload(Duration::from_millis(1)),
            Err(LifecycleError::UnloadTimeout {
                generation_id: 11,
                active_leases: 1
            })
        ));
        release_tx.send(()).expect("release");
        worker.join().expect("worker");
        first
            .wait_for_unload(Duration::from_secs(1))
            .expect("first unload");
        slot.shutdown(Duration::from_secs(1)).expect("shutdown");
    }

    #[test]
    fn invalid_generation_limits_fail_before_runtime_activation() {
        let limits = RuntimeLimits {
            sensitive_arena_size: MAX_SENSITIVE_ARENA_SIZE + 1,
            ..RuntimeLimits::default()
        };
        let result =
            RuntimeGeneration::with_limits(1, ArtifactIndex::empty(), Capabilities::NONE, limits);
        assert!(matches!(result, Err(LifecycleError::InvalidLimit { .. })));
        let context = ThreadRuntimeContext::new(RuntimeLimits::default()).expect("context");
        drop(context);
    }
}
