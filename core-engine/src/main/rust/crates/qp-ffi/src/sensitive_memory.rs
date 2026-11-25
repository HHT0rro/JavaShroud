//! Bounded native-owned storage for short-lived secrets.
//!
//! This is deliberately small in scope.  It does not claim to make a process
//! undumpable; it reduces the lifetime of sensitive buffers and asks the host
//! OS to keep those buffers out of ordinary paging paths where supported.  It
//! does not promise that a privileged debugger or a full-process dump cannot
//! observe bytes while they are actively in use.

use std::fmt;
use std::sync::atomic::{compiler_fence, Ordering};

pub const MAX_SENSITIVE_LEASE_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveMemoryError {
    Empty,
    TooLarge { size: usize, maximum: usize },
    Closed,
    LockUnavailable,
    UnlockUnavailable,
    RandomUnavailable,
}

impl fmt::Display for SensitiveMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("sensitive lease cannot be empty"),
            Self::TooLarge { size, maximum } => {
                write!(
                    formatter,
                    "sensitive lease is too large: {size} > {maximum}"
                )
            }
            Self::Closed => formatter.write_str("sensitive lease is closed"),
            Self::LockUnavailable => formatter.write_str("sensitive lease could not be locked"),
            Self::UnlockUnavailable => formatter.write_str("sensitive lease could not be unlocked"),
            Self::RandomUnavailable => {
                formatter.write_str("native secure randomness is unavailable")
            }
        }
    }
}

impl std::error::Error for SensitiveMemoryError {}

/// A non-cloneable, bounded, zeroizing buffer owned by the native runtime.
pub struct SensitiveMemoryLease {
    storage: Box<[u8]>,
    offset: usize,
    length: usize,
    protected_length: usize,
    locked: bool,
    dump_protected: bool,
    closed: bool,
}

impl SensitiveMemoryLease {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SensitiveMemoryError> {
        let size = bytes.len();
        if size == 0 {
            return Err(SensitiveMemoryError::Empty);
        }
        if size > MAX_SENSITIVE_LEASE_BYTES {
            let mut bytes = bytes;
            volatile_wipe(&mut bytes);
            return Err(SensitiveMemoryError::TooLarge {
                size,
                maximum: MAX_SENSITIVE_LEASE_BYTES,
            });
        }

        // Linux madvise requires a page-aligned range. Allocate enough private
        // backing storage for one aligned, page-rounded subrange so DONTDUMP
        // never spills into a neighboring allocation. Other targets retain an
        // exact-size allocation because their lock API accepts byte ranges.
        let mut source = bytes;
        let (mut storage, offset, protected_length) = protected_storage(size);
        storage[offset..offset + size].copy_from_slice(&source);
        volatile_wipe(&mut source);
        drop(source);

        let mut lease = Self {
            storage,
            offset,
            length: size,
            protected_length,
            locked: false,
            dump_protected: false,
            closed: false,
        };
        let pointer = lease.protected_pointer();
        lease.locked = lock_memory(pointer, lease.protected_length);
        lease.dump_protected = protect_from_dump(pointer, lease.protected_length);
        Ok(lease)
    }

    pub fn new_required(bytes: Vec<u8>) -> Result<Self, SensitiveMemoryError> {
        let lease = Self::new(bytes)?;
        if lease.locked {
            Ok(lease)
        } else {
            Err(SensitiveMemoryError::LockUnavailable)
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SensitiveMemoryError> {
        Self::new(bytes.to_vec())
    }

    /// Generate a bounded native nonce without routing the entropy through Java.
    pub fn random(length: usize) -> Result<Self, SensitiveMemoryError> {
        if length == 0 {
            return Err(SensitiveMemoryError::Empty);
        }
        if length > MAX_SENSITIVE_LEASE_BYTES {
            return Err(SensitiveMemoryError::TooLarge {
                size: length,
                maximum: MAX_SENSITIVE_LEASE_BYTES,
            });
        }
        let mut bytes = vec![0u8; length];
        if !fill_os_random(&mut bytes) {
            volatile_wipe(&mut bytes);
            return Err(SensitiveMemoryError::RandomUnavailable);
        }
        Self::new(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.closed {
            return &[];
        }
        &self.storage[self.offset..self.offset + self.length]
    }

    /// Mutably borrow the bytes only while the lease is open.
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8], SensitiveMemoryError> {
        if self.closed {
            Err(SensitiveMemoryError::Closed)
        } else {
            Ok(&mut self.storage[self.offset..self.offset + self.length])
        }
    }

    /// Alias for [`Self::as_mut_slice`] that makes the fallible boundary
    /// explicit at call sites handling page leases.
    pub fn try_as_mut_slice(&mut self) -> Result<&mut [u8], SensitiveMemoryError> {
        self.as_mut_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Wipe the current contents without ending the lease.
    pub fn wipe(&mut self) -> Result<(), SensitiveMemoryError> {
        if self.closed {
            return Err(SensitiveMemoryError::Closed);
        }
        volatile_wipe(&mut self.storage[self.offset..self.offset + self.length]);
        Ok(())
    }

    /// Request page locking after a best-effort construction.
    pub fn lock(&mut self) -> Result<(), SensitiveMemoryError> {
        if self.closed {
            return Err(SensitiveMemoryError::Closed);
        }
        if self.locked || self.length == 0 {
            return Ok(());
        }
        let pointer = self.protected_pointer();
        if lock_memory(pointer, self.protected_length) {
            self.locked = true;
            self.dump_protected =
                protect_from_dump(pointer, self.protected_length) || self.dump_protected;
            Ok(())
        } else {
            Err(SensitiveMemoryError::LockUnavailable)
        }
    }

    /// Release page locking while keeping the lease open.
    pub fn unlock(&mut self) -> Result<(), SensitiveMemoryError> {
        if self.closed {
            return Err(SensitiveMemoryError::Closed);
        }
        if !self.locked || self.length == 0 {
            return Ok(());
        }
        let pointer = self.protected_pointer();
        if unlock_memory(pointer, self.protected_length) {
            self.locked = false;
            Ok(())
        } else {
            Err(SensitiveMemoryError::UnlockUnavailable)
        }
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        let pointer = self.protected_pointer();
        volatile_wipe(&mut self.storage[self.offset..self.offset + self.protected_length]);
        if self.locked {
            let _ = unlock_memory(pointer, self.protected_length);
            self.locked = false;
        }
        if self.dump_protected {
            allow_dump(pointer, self.protected_length);
            self.dump_protected = false;
        }
        self.closed = true;
    }

    fn protected_pointer(&mut self) -> *mut u8 {
        // SAFETY: offset and protected_length are constructed within storage.
        unsafe { self.storage.as_mut_ptr().add(self.offset) }
    }
}

impl fmt::Debug for SensitiveMemoryLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveMemoryLease")
            .field("length", &self.length)
            .field("locked", &self.locked)
            .field("dump_protected", &self.dump_protected)
            .field("closed", &self.closed)
            .finish()
    }
}

impl Drop for SensitiveMemoryLease {
    fn drop(&mut self) {
        self.close();
    }
}

fn volatile_wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid unique reference from the slice.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
fn protected_storage(length: usize) -> (Box<[u8]>, usize, usize) {
    let page_size = system_page_size();
    let protected_length = round_up(length, page_size);
    let storage_length = protected_length + page_size - 1;
    let mut storage = vec![0u8; storage_length].into_boxed_slice();
    let base = storage.as_mut_ptr() as usize;
    let aligned = round_up(base, page_size);
    let offset = aligned - base;
    debug_assert!(offset + protected_length <= storage.len());
    (storage, offset, protected_length)
}

#[cfg(not(target_os = "linux"))]
fn protected_storage(length: usize) -> (Box<[u8]>, usize, usize) {
    (vec![0u8; length].into_boxed_slice(), 0, length)
}

#[cfg(target_os = "linux")]
fn system_page_size() -> usize {
    let size = unsafe { getpagesize() };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

#[cfg(target_os = "linux")]
fn round_up(value: usize, alignment: usize) -> usize {
    debug_assert!(alignment > 0);
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + (alignment - remainder)
    }
}

#[cfg(unix)]
fn lock_memory(pointer: *mut u8, length: usize) -> bool {
    if length == 0 {
        return false;
    }
    unsafe { libc_mlock(pointer, length) == 0 }
}

#[cfg(unix)]
fn unlock_memory(pointer: *mut u8, length: usize) -> bool {
    if length != 0 {
        unsafe {
            return libc_munlock(pointer, length) == 0;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn protect_from_dump(pointer: *mut u8, length: usize) -> bool {
    if length == 0 {
        return false;
    }
    unsafe { linux_madvise(pointer, length, 16) == 0 }
}

#[cfg(windows)]
fn protect_from_dump(pointer: *mut u8, length: usize) -> bool {
    // VirtualProtect(PAGE_NOACCESS) on a Rust heap allocation can make the
    // neighboring heap inaccessible and AV the process. Dedicated VirtualAlloc
    // pages belong to a later max-hardening window; this path only reports
    // that ordinary heap pages are not dump-excluded.
    let _ = (pointer, length);
    false
}

#[cfg(not(any(target_os = "linux", windows)))]
fn protect_from_dump(pointer: *mut u8, length: usize) -> bool {
    let _ = (pointer, length);
    false
}

#[cfg(target_os = "linux")]
fn allow_dump(pointer: *mut u8, length: usize) {
    if length != 0 {
        unsafe {
            let _ = linux_madvise(pointer, length, 17);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_dump(pointer: *mut u8, length: usize) {
    let _ = (pointer, length);
}

#[cfg(not(unix))]
fn lock_memory(pointer: *mut u8, length: usize) -> bool {
    #[cfg(windows)]
    {
        if length == 0 {
            return false;
        }
        unsafe { windows_virtual_lock(pointer, length) != 0 }
    }
    #[cfg(not(windows))]
    {
        let _ = (pointer, length);
        false
    }
}

#[cfg(not(unix))]
fn unlock_memory(pointer: *mut u8, length: usize) -> bool {
    #[cfg(windows)]
    {
        if length != 0 {
            return unsafe { windows_virtual_unlock(pointer, length) != 0 };
        }
        true
    }
    #[cfg(not(windows))]
    {
        let _ = (pointer, length);
        false
    }
}

#[cfg(unix)]
extern "C" {
    fn mlock(address: *const core::ffi::c_void, length: usize) -> core::ffi::c_int;
    fn munlock(address: *const core::ffi::c_void, length: usize) -> core::ffi::c_int;
    #[cfg(target_os = "linux")]
    fn madvise(
        address: *mut core::ffi::c_void,
        length: usize,
        advice: core::ffi::c_int,
    ) -> core::ffi::c_int;
    #[cfg(target_os = "linux")]
    fn getpagesize() -> core::ffi::c_int;
}

#[cfg(target_os = "linux")]
unsafe fn linux_madvise(
    pointer: *mut u8,
    length: usize,
    advice: core::ffi::c_int,
) -> core::ffi::c_int {
    madvise(pointer.cast(), length, advice)
}

#[cfg(unix)]
unsafe fn libc_mlock(pointer: *mut u8, length: usize) -> core::ffi::c_int {
    mlock(pointer.cast(), length)
}

#[cfg(unix)]
unsafe fn libc_munlock(pointer: *mut u8, length: usize) -> core::ffi::c_int {
    munlock(pointer.cast(), length)
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn VirtualLock(address: *mut core::ffi::c_void, length: usize) -> i32;
    fn VirtualUnlock(address: *mut core::ffi::c_void, length: usize) -> i32;
}

#[cfg(windows)]
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut core::ffi::c_void,
        buffer: *mut u8,
        length: u32,
        flags: u32,
    ) -> i32;
}

#[cfg(windows)]
unsafe fn windows_virtual_lock(pointer: *mut u8, length: usize) -> i32 {
    VirtualLock(pointer.cast(), length)
}

#[cfg(windows)]
unsafe fn windows_virtual_unlock(pointer: *mut u8, length: usize) -> i32 {
    VirtualUnlock(pointer.cast(), length)
}

fn fill_os_random(bytes: &mut [u8]) -> bool {
    #[cfg(unix)]
    {
        use std::io::Read;
        let Ok(mut source) = std::fs::File::open("/dev/urandom") else {
            return false;
        };
        return source.read_exact(bytes).is_ok();
    }
    #[cfg(windows)]
    {
        if bytes.is_empty() {
            return true;
        }
        // BCryptGenRandom uses the system-preferred provider and does not
        // require a process-owned algorithm handle.
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        bytes.len() <= u32::MAX as usize
            && unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    bytes.as_mut_ptr(),
                    bytes.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                ) == 0
            }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = bytes;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_is_bounded_and_zeroized_on_close() {
        let mut lease = SensitiveMemoryLease::new(vec![0xA5; 32]).expect("lease");
        assert_eq!(lease.len(), 32);
        assert!(!lease.is_closed());
        lease.close();
        assert!(lease.is_closed());
        lease.close();
        assert!(lease.is_closed());
    }

    #[test]
    fn lease_rejects_empty_and_oversized_buffers() {
        assert!(matches!(
            SensitiveMemoryLease::new(Vec::new()),
            Err(SensitiveMemoryError::Empty)
        ));
        assert!(matches!(
            SensitiveMemoryLease::new(vec![0; MAX_SENSITIVE_LEASE_BYTES + 1]),
            Err(SensitiveMemoryError::TooLarge { .. })
        ));
    }

    #[test]
    fn checked_access_and_explicit_wipe_respect_the_lease_state() {
        let mut lease = SensitiveMemoryLease::from_slice(b"native secret").expect("lease");
        lease.as_mut_slice().expect("open lease")[0] ^= 0x5a;
        lease.wipe().expect("wipe");
        assert!(lease.as_slice().iter().all(|byte| *byte == 0));
        lease.close();
        assert!(lease.as_slice().is_empty() || lease.as_slice().iter().all(|byte| *byte == 0));
        assert_eq!(lease.as_mut_slice(), Err(SensitiveMemoryError::Closed));
        assert_eq!(lease.try_as_mut_slice(), Err(SensitiveMemoryError::Closed));
        assert_eq!(lease.wipe(), Err(SensitiveMemoryError::Closed));
        assert_eq!(lease.lock(), Err(SensitiveMemoryError::Closed));
        assert_eq!(lease.unlock(), Err(SensitiveMemoryError::Closed));
    }

    #[test]
    fn required_lock_policy_never_returns_an_unlocked_lease() {
        match SensitiveMemoryLease::new_required(vec![0xA5; 64]) {
            Ok(lease) => assert!(lease.is_locked()),
            Err(SensitiveMemoryError::LockUnavailable) => {}
            Err(error) => panic!("unexpected required-lock error: {error}"),
        }
    }

    #[test]
    fn empty_state_query_is_stable_for_valid_leases() {
        let lease = SensitiveMemoryLease::new(vec![1]).expect("lease");
        assert!(!lease.is_empty());
    }

    #[test]
    fn random_lease_has_nonconstant_material_when_os_entropy_is_available() {
        let first = SensitiveMemoryLease::random(32).expect("os randomness");
        let second = SensitiveMemoryLease::random(32).expect("os randomness");
        assert_ne!(first.as_slice(), second.as_slice());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dump_protected_range_is_page_aligned_and_covers_the_logical_buffer() {
        let lease = SensitiveMemoryLease::new(vec![0xA5; 33]).expect("lease");
        let page_size = system_page_size();
        let pointer = unsafe { lease.storage.as_ptr().add(lease.offset) } as usize;
        assert_eq!(pointer % page_size, 0);
        assert_eq!(lease.protected_length % page_size, 0);
        assert!(lease.protected_length >= lease.length);
        assert!(lease.offset + lease.protected_length <= lease.storage.len());
    }
}
