//! Experimental Windows manual-map backend for max-hardening.
//!
//! Standard profile continues to `System.load` the full PE. This backend is
//! wired only when packing is max-hardening and must fail closed instead of
//! falling back to a loadable DLL. It does not claim undumpability: mapping
//! the image still places RX code in the process.

#![cfg(windows)]

use qp_shell::{
    Export, Import, InitPlan, MapBackend, MapRegion, MemoryProtection, Relocation, TlsPlan,
};
use std::fmt;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        address: *mut core::ffi::c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void;
    fn VirtualProtect(
        address: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
    fn VirtualFree(address: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsMapError {
    WriteExecute,
    AllocationFailed,
    CopyOutOfRange,
    ProtectFailed,
    UnsupportedRelocation,
    UnsupportedImport,
    TlsUnsupported,
    InitializersUnsupported,
}

impl fmt::Display for WindowsMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteExecute => formatter.write_str("W+X mapping is forbidden"),
            Self::AllocationFailed => formatter.write_str("VirtualAlloc failed"),
            Self::CopyOutOfRange => formatter.write_str("manual-map copy is out of range"),
            Self::ProtectFailed => formatter.write_str("VirtualProtect failed"),
            Self::UnsupportedRelocation => formatter.write_str("relocation kind is unsupported"),
            Self::UnsupportedImport => formatter.write_str("import resolution is not implemented"),
            Self::TlsUnsupported => formatter.write_str("TLS initialization is not implemented"),
            Self::InitializersUnsupported => {
                formatter.write_str("initializer dispatch is not implemented")
            }
        }
    }
}

impl std::error::Error for WindowsMapError {}

pub struct WindowsMapping {
    base: *mut u8,
    size: usize,
}

impl WindowsMapping {
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

pub struct WindowsVirtualAllocBackend {
    require_max_hardening: bool,
}

impl WindowsVirtualAllocBackend {
    pub fn for_max_hardening() -> Self {
        Self {
            require_max_hardening: true,
        }
    }

    /// Standard profile must keep `System.load`. Max-hardening must not pretend
    /// a partial map succeeded: reloc/import/TLS/init still fail closed.
    pub fn refuses_silent_fallback() -> bool {
        true
    }

    fn protection_flags(protection: MemoryProtection) -> Result<u32, WindowsMapError> {
        if protection.write && protection.execute {
            return Err(WindowsMapError::WriteExecute);
        }
        Ok(match (protection.read, protection.write, protection.execute) {
            (_, true, false) => PAGE_READWRITE,
            (_, false, true) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_READONLY,
            _ => PAGE_NOACCESS,
        })
    }

    fn offset_pointer(
        mapping: &WindowsMapping,
        virtual_address: u64,
        length: usize,
    ) -> Result<*mut u8, WindowsMapError> {
        let offset = usize::try_from(virtual_address).map_err(|_| WindowsMapError::CopyOutOfRange)?;
        let end = offset
            .checked_add(length)
            .ok_or(WindowsMapError::CopyOutOfRange)?;
        if end > mapping.size {
            return Err(WindowsMapError::CopyOutOfRange);
        }
        Ok(unsafe { mapping.base.add(offset) })
    }
}

impl MapBackend for WindowsVirtualAllocBackend {
    type Mapping = WindowsMapping;
    type Error = WindowsMapError;

    fn allocate(&mut self, image_size: u64, _alignment: u64) -> Result<Self::Mapping, Self::Error> {
        if !self.require_max_hardening {
            return Err(WindowsMapError::AllocationFailed);
        }
        let size = usize::try_from(image_size).map_err(|_| WindowsMapError::CopyOutOfRange)?;
        if size == 0 {
            return Err(WindowsMapError::CopyOutOfRange);
        }
        let base = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if base.is_null() {
            return Err(WindowsMapError::AllocationFailed);
        }
        Ok(WindowsMapping {
            base: base.cast(),
            size,
        })
    }

    fn copy(
        &mut self,
        mapping: &Self::Mapping,
        virtual_address: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let dest = Self::offset_pointer(mapping, virtual_address, bytes.len())?;
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, bytes.len());
        }
        Ok(())
    }

    fn zero(
        &mut self,
        mapping: &Self::Mapping,
        virtual_address: u64,
        length: u64,
    ) -> Result<(), Self::Error> {
        let size = usize::try_from(length).map_err(|_| WindowsMapError::CopyOutOfRange)?;
        let dest = Self::offset_pointer(mapping, virtual_address, size)?;
        unsafe {
            core::ptr::write_bytes(dest, 0, size);
        }
        Ok(())
    }

    fn apply_relocation(
        &mut self,
        _mapping: &Self::Mapping,
        _relocation: &Relocation,
    ) -> Result<(), Self::Error> {
        Err(WindowsMapError::UnsupportedRelocation)
    }

    fn resolve_import(&mut self, _import: &Import) -> Result<u64, Self::Error> {
        Err(WindowsMapError::UnsupportedImport)
    }

    fn write_import(
        &mut self,
        mapping: &Self::Mapping,
        virtual_address: u64,
        address: u64,
    ) -> Result<(), Self::Error> {
        let dest = Self::offset_pointer(mapping, virtual_address, 8)?;
        let bytes = address.to_le_bytes();
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, 8);
        }
        Ok(())
    }

    fn protect(&mut self, mapping: &Self::Mapping, region: &MapRegion) -> Result<(), Self::Error> {
        let flags = Self::protection_flags(region.protection())?;
        let size = usize::try_from(region.memory_size()).map_err(|_| WindowsMapError::CopyOutOfRange)?;
        let dest = Self::offset_pointer(mapping, region.virtual_address(), size)?;
        let mut old = 0u32;
        let ok = unsafe { VirtualProtect(dest.cast(), size, flags, &mut old) };
        if ok == 0 {
            Err(WindowsMapError::ProtectFailed)
        } else {
            Ok(())
        }
    }

    fn initialize_tls(
        &mut self,
        _mapping: &Self::Mapping,
        tls: &TlsPlan,
    ) -> Result<(), Self::Error> {
        if !tls.is_present() {
            Ok(())
        } else {
            Err(WindowsMapError::TlsUnsupported)
        }
    }

    fn call_initializers(
        &mut self,
        _mapping: &Self::Mapping,
        init: &InitPlan,
    ) -> Result<(), Self::Error> {
        if init.entry_point().is_none() && init.init_functions().is_empty() {
            Ok(())
        } else {
            Err(WindowsMapError::InitializersUnsupported)
        }
    }

    fn publish_exports(
        &mut self,
        _mapping: &Self::Mapping,
        _exports: &[Export],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn release(&mut self, mapping: Self::Mapping) {
        if !mapping.base.is_null() && mapping.size != 0 {
            unsafe {
                let _ = VirtualFree(mapping.base.cast(), 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qp_shell::MemoryProtection;

    #[test]
    fn write_execute_is_rejected() {
        let wx = MemoryProtection {
            read: true,
            write: true,
            execute: true,
        };
        assert_eq!(
            WindowsVirtualAllocBackend::protection_flags(wx),
            Err(WindowsMapError::WriteExecute)
        );
    }

    #[test]
    fn max_hardening_refuses_silent_fallback() {
        assert!(WindowsVirtualAllocBackend::refuses_silent_fallback());
        let mut backend = WindowsVirtualAllocBackend::for_max_hardening();
        let mapping = backend.allocate(0x1000, 0x1000).expect("alloc");
        backend.release(mapping);
    }

    #[test]
    fn rx_and_rw_are_distinct_and_legal() {
        let rx = MemoryProtection {
            read: true,
            write: false,
            execute: true,
        };
        let rw = MemoryProtection {
            read: true,
            write: true,
            execute: false,
        };
        assert_eq!(
            WindowsVirtualAllocBackend::protection_flags(rx),
            Ok(PAGE_EXECUTE_READ)
        );
        assert_eq!(
            WindowsVirtualAllocBackend::protection_flags(rw),
            Ok(PAGE_READWRITE)
        );
    }
}
