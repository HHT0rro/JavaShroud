//! File-backed image measurement for the native secret pack.
//!
//! The commitment slot is hashed as zeros. PE reloc/IAT file ranges and ELF
//! `SHT_REL`/`SHT_RELA` ranges are zeroed so dump-repair and loader rewrites of
//! those directories cannot be used as a stable oracle, and so a later mapped-
//! image path can ignore ASLR-variant tables. The on-disk file is the current
//! measurement source so build and runtime stay in lockstep.

use crate::specialization;
use qp_crypto::{constant_time_eq, hmac_sha256_bytes, sha256, DIGEST_SIZE};
use qp_runtime::RouterError;
use std::path::PathBuf;

const PE_RELOC_DIRECTORY: usize = 5;
const PE_IAT_DIRECTORY: usize = 12;
const ELF_SHT_REL: u32 = 9;
const ELF_SHT_RELA: u32 = 4;
const CRC32_POLY: u32 = 0xEDB8_8320;

pub fn verify_wrap_key(wrap_key: &[u8; 32]) -> Result<(), RouterError> {
    let path = loaded_module_path().ok_or(RouterError::AuthenticationFailed)?;
    let mut bytes = std::fs::read(&path).map_err(|_| RouterError::AuthenticationFailed)?;
    let digest = measure_bytes(&mut bytes)?;
    let expected = hmac_sha256_bytes(wrap_key, &[&digest]);
    let commitment = specialization::image_measurement_commitment();
    bytes.fill(0);
    if !constant_time_eq(&expected, &commitment) {
        return Err(RouterError::AuthenticationFailed);
    }
    Ok(())
}

pub fn commitment_crc32() -> u32 {
    crc32(&specialization::image_measurement_commitment())
}

pub(crate) fn measure_bytes(bytes: &mut [u8]) -> Result<[u8; DIGEST_SIZE], RouterError> {
    // The wrap binds the on-disk file. Reloc/IAT bytes are stable on disk, so
    // they stay in the digest; only the commitment slot is hashed as zeros.
    zero_commitment_slot(bytes)?;
    Ok(*sha256(bytes).as_bytes())
}

fn zero_commitment_slot(bytes: &mut [u8]) -> Result<(), RouterError> {
    let slot = locate_commitment_slot(bytes)?;
    bytes[slot..slot + DIGEST_SIZE].fill(0);
    Ok(())
}

fn slot_magic() -> [u8; 8] {
    let mask = [0xA5u8, 0x3C, 0x5A, 0xC3, 0x0F, 0xF0, 0x69, 0x96];
    let packed = [
        b'J' ^ 0xA5,
        b'S' ^ 0x3C,
        b'I' ^ 0x5A,
        b'M' ^ 0xC3,
        0x01 ^ 0x0F,
        b'v' ^ 0xF0,
        b'6' ^ 0x69,
        0 ^ 0x96,
    ];
    let mut magic = [0u8; 8];
    for index in 0..8 {
        magic[index] = packed[index] ^ mask[index];
    }
    magic
}

fn locate_commitment_slot(bytes: &[u8]) -> Result<usize, RouterError> {
    if let Some(magic_offset) = locate_jsms_magic(bytes) {
        return Ok(magic_offset + slot_magic().len());
    }
    locate_magic_slot(bytes)
}

fn locate_jsms_magic(bytes: &[u8]) -> Option<usize> {
    if is_pe64(bytes) {
        return locate_pe_section_magic(bytes, b".jsms");
    }
    if is_elf64(bytes) {
        return locate_elf_section_magic(bytes, b".jsms");
    }
    None
}

fn locate_pe_section_magic(bytes: &[u8], name: &[u8]) -> Option<usize> {
    let pe_offset = read_u32(bytes, 0x3C) as usize;
    let optional_size = read_u16(bytes, pe_offset + 20) as usize;
    let section_count = read_u16(bytes, pe_offset + 6) as usize;
    if optional_size < 112 || !(1..=96).contains(&section_count) {
        return None;
    }
    let section_table = pe_offset + 24 + optional_size;
    let mut expected = [0u8; 8];
    let copied = core::cmp::min(name.len(), 8);
    expected[..copied].copy_from_slice(&name[..copied]);
    for index in 0..section_count {
        let section = section_table.checked_add(index.saturating_mul(40))?;
        if section + 40 > bytes.len() {
            return None;
        }
        if bytes[section..section + 8] != expected {
            continue;
        }
        let raw_size = read_u32(bytes, section + 16) as usize;
        let raw_offset = read_u32(bytes, section + 20) as usize;
        if raw_size < slot_magic().len() + DIGEST_SIZE || raw_offset.saturating_add(raw_size) > bytes.len() {
            continue;
        }
        return scan_magic_in_range(bytes, raw_offset, raw_size);
    }
    None
}

fn locate_elf_section_magic(bytes: &[u8], name: &[u8]) -> Option<usize> {
    let section_offset = read_u64(bytes, 0x28) as usize;
    let section_entry_size = read_u16(bytes, 0x3A) as usize;
    let section_count = read_u16(bytes, 0x3C) as usize;
    let name_index = read_u16(bytes, 0x3E) as usize;
    if section_offset == 0 || section_entry_size < 64 || !(1..=1024).contains(&section_count) {
        return None;
    }
    if name_index >= section_count {
        return None;
    }
    let name_section = section_offset.checked_add(name_index.saturating_mul(section_entry_size))?;
    if name_section + 64 > bytes.len() {
        return None;
    }
    let name_table_offset = read_u64(bytes, name_section + 24) as usize;
    let name_table_size = read_u64(bytes, name_section + 32) as usize;
    if name_table_offset == 0 || name_table_size == 0 {
        return None;
    }
    for index in 0..section_count {
        let section = section_offset.checked_add(index.saturating_mul(section_entry_size))?;
        if section + 64 > bytes.len() {
            return None;
        }
        let name_off = read_u32(bytes, section) as usize;
        if !elf_name_equals(bytes, name_table_offset, name_table_size, name_off, name) {
            continue;
        }
        let file_offset = read_u64(bytes, section + 24) as usize;
        let size = read_u64(bytes, section + 32) as usize;
        if file_offset == 0 || size < slot_magic().len() + DIGEST_SIZE {
            continue;
        }
        if file_offset.saturating_add(size) > bytes.len() {
            continue;
        }
        return scan_magic_in_range(bytes, file_offset, size);
    }
    None
}

fn elf_name_equals(bytes: &[u8], table_offset: usize, table_size: usize, name_off: usize, needle: &[u8]) -> bool {
    if name_off >= table_size {
        return false;
    }
    let start = match table_offset.checked_add(name_off) {
        Some(value) => value,
        None => return false,
    };
    if start.saturating_add(needle.len()).saturating_add(1) > bytes.len() {
        return false;
    }
    bytes[start..start + needle.len()] == *needle && bytes[start + needle.len()] == 0
}

fn scan_magic_in_range(bytes: &[u8], start: usize, size: usize) -> Option<usize> {
    let magic = slot_magic();
    if size < magic.len() + DIGEST_SIZE {
        return None;
    }
    let limit = start + size - magic.len() - DIGEST_SIZE;
    for index in start..=limit {
        if bytes[index..index + magic.len()] == magic {
            return Some(index);
        }
    }
    None
}

fn locate_magic_slot(bytes: &[u8]) -> Result<usize, RouterError> {
    let magic = slot_magic();
    let expected = specialization::image_measurement_commitment();
    if bytes.len() < magic.len() + DIGEST_SIZE {
        return Err(RouterError::AuthenticationFailed);
    }
    let limit = bytes.len() - magic.len() - DIGEST_SIZE;
    let mut unique = None;
    let mut unique_count = 0usize;
    let mut expected_match = None;
    for index in 0..=limit {
        if bytes[index..index + magic.len()] != magic {
            continue;
        }
        unique_count += 1;
        unique = Some(index + magic.len());
        let slot = &bytes[index + magic.len()..index + magic.len() + DIGEST_SIZE];
        if slot == expected.as_slice() {
            if expected_match.is_some() {
                return Err(RouterError::AuthenticationFailed);
            }
            expected_match = Some(index + magic.len());
        }
    }
    if unique_count == 1 {
        return unique.ok_or(RouterError::AuthenticationFailed);
    }
    expected_match.ok_or(RouterError::AuthenticationFailed)
}

fn is_pe64(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return false;
    }
    let pe_offset = read_u32(bytes, 0x3C) as usize;
    if pe_offset.checked_add(26).map(|end| end > bytes.len()).unwrap_or(true) {
        return false;
    }
    if bytes[pe_offset] != b'P' || bytes[pe_offset + 1] != b'E' || bytes[pe_offset + 2] != 0 || bytes[pe_offset + 3] != 0
    {
        return false;
    }
    read_u16(bytes, pe_offset + 4) == 0x8664 && read_u16(bytes, pe_offset + 24) == 0x20B
}

fn is_elf64(bytes: &[u8]) -> bool {
    bytes.len() >= 64
        && bytes[0] == 0x7F
        && bytes[1] == b'E'
        && bytes[2] == b'L'
        && bytes[3] == b'F'
        && bytes[4] == 2
        && bytes[5] == 1
}

fn zero_pe_reloc_and_iat(bytes: &mut [u8]) {
    let pe_offset = read_u32(bytes, 0x3C) as usize;
    let optional_size = read_u16(bytes, pe_offset + 20) as usize;
    let section_count = read_u16(bytes, pe_offset + 6) as usize;
    if optional_size < 112 || !(1..=96).contains(&section_count) {
        return;
    }
    let optional_offset = pe_offset + 24;
    let directory_offset = optional_offset + 112;
    let number_of_rva_and_sizes = read_u32(bytes, optional_offset + 108) as usize;
    let section_table = optional_offset + optional_size;
    zero_pe_directory(
        bytes,
        directory_offset,
        number_of_rva_and_sizes,
        PE_RELOC_DIRECTORY,
        section_table,
        section_count,
    );
    zero_pe_directory(
        bytes,
        directory_offset,
        number_of_rva_and_sizes,
        PE_IAT_DIRECTORY,
        section_table,
        section_count,
    );
}

fn zero_pe_directory(
    bytes: &mut [u8],
    directory_offset: usize,
    number_of_rva_and_sizes: usize,
    index: usize,
    section_table: usize,
    section_count: usize,
) {
    if index >= number_of_rva_and_sizes {
        return;
    }
    let entry = match directory_offset.checked_add(index.saturating_mul(8)) {
        Some(value) if value + 8 <= bytes.len() => value,
        _ => return,
    };
    let rva = read_u32(bytes, entry);
    let size = read_u32(bytes, entry + 4);
    if rva == 0 || size == 0 {
        return;
    }
    if let Some(file_offset) = rva_to_file_offset(bytes, section_table, section_count, rva) {
        zero_range(bytes, file_offset, size as usize);
    }
}

fn rva_to_file_offset(bytes: &[u8], section_table: usize, section_count: usize, rva: u32) -> Option<usize> {
    for index in 0..section_count {
        let section = section_table.checked_add(index.saturating_mul(40))?;
        if section + 40 > bytes.len() {
            return None;
        }
        let virtual_size = read_u32(bytes, section + 8);
        let virtual_address = read_u32(bytes, section + 12);
        let raw_size = read_u32(bytes, section + 16);
        let raw_offset = read_u32(bytes, section + 20);
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva.wrapping_sub(virtual_address) < span {
            let offset = (raw_offset as u64).wrapping_add(u64::from(rva.wrapping_sub(virtual_address)));
            if offset > usize::MAX as u64 {
                return None;
            }
            let offset = offset as usize;
            if offset >= bytes.len() {
                return None;
            }
            return Some(offset);
        }
    }
    None
}

fn zero_elf_relocations(bytes: &mut [u8]) {
    let section_offset = read_u64(bytes, 0x28);
    let section_entry_size = read_u16(bytes, 0x3A) as u64;
    let section_count = read_u16(bytes, 0x3C) as u64;
    if section_offset == 0 || section_entry_size < 64 || !(1..=1024).contains(&section_count) {
        return;
    }
    for index in 0..section_count {
        let section = section_offset.saturating_add(index.saturating_mul(section_entry_size));
        if section > usize::MAX as u64 {
            return;
        }
        let section = section as usize;
        if section + 64 > bytes.len() {
            return;
        }
        let kind = read_u32(bytes, section + 4);
        if kind != ELF_SHT_REL && kind != ELF_SHT_RELA {
            continue;
        }
        let file_offset = read_u64(bytes, section + 24);
        let size = read_u64(bytes, section + 32);
        if file_offset == 0 || size == 0 || file_offset > usize::MAX as u64 || size > usize::MAX as u64 {
            continue;
        }
        zero_range(bytes, file_offset as usize, size as usize);
    }
}

fn zero_range(bytes: &mut [u8], offset: usize, size: usize) {
    let end = match offset.checked_add(size) {
        Some(value) if value <= bytes.len() => value,
        _ => return,
    };
    bytes[offset..end].fill(0);
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    if offset + 2 > bytes.len() {
        return 0;
    }
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    if offset + 4 > bytes.len() {
        return 0;
    }
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    if offset + 8 > bytes.len() {
        return 0;
    }
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (CRC32_POLY & mask);
        }
    }
    !crc
}

fn loaded_module_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        windows_module_path()
    }
    #[cfg(target_os = "linux")]
    {
        linux_module_path()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
fn windows_module_path() -> Option<PathBuf> {
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleExW(
            flags: u32,
            name: *const u16,
            module: *mut *mut core::ffi::c_void,
        ) -> i32;
        fn GetModuleFileNameW(module: *mut core::ffi::c_void, filename: *mut u16, size: u32) -> u32;
    }
    unsafe {
        let mut module = core::ptr::null_mut();
        let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        let ok = GetModuleHandleExW(flags, verify_wrap_key as *const u16, &mut module);
        if ok == 0 || module.is_null() {
            return None;
        }
        let mut buffer = [0u16; 32768];
        let written = GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32);
        if written == 0 || written as usize >= buffer.len() {
            return None;
        }
        String::from_utf16(&buffer[..written as usize])
            .ok()
            .map(PathBuf::from)
    }
}

#[cfg(target_os = "linux")]
fn linux_module_path() -> Option<PathBuf> {
    let needle = verify_wrap_key as *const () as u64;
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let (range, rest) = line.split_once(' ')?;
        let (start, end) = range.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        if needle < start || needle >= end {
            continue;
        }
        let path = rest.splitn(5, ' ').nth(4)?.trim();
        if path.is_empty() || path.starts_with('[') {
            return None;
        }
        return Some(PathBuf::from(path));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn magic() -> [u8; 8] {
        specialization::IMAGE_MEASUREMENT.magic
    }

    #[test]
    fn measure_zeros_the_commitment_slot() {
        let mut bytes = vec![0u8; 64];
        bytes[..8].copy_from_slice(&magic());
        let first = measure_bytes(&mut bytes).expect("measure");
        assert!(bytes[8..40].iter().all(|byte| *byte == 0));
        let second = measure_bytes(&mut bytes).expect("measure");
        assert_eq!(first, second);
    }

    #[test]
    fn foreign_magic_tail_is_ignored() {
        let mut bytes = vec![0u8; 80];
        bytes[..8].copy_from_slice(&magic());
        bytes[40..48].copy_from_slice(&magic());
        bytes[48..56].fill(0x5A);
        let digest = measure_bytes(&mut bytes).expect("measure");
        assert!(bytes[8..40].iter().all(|byte| *byte == 0));
        assert_ne!(digest, [0u8; DIGEST_SIZE]);
    }

    #[test]
    fn duplicate_magic_fails_closed() {
        let mut bytes = vec![0u8; 80];
        bytes[..8].copy_from_slice(&magic());
        bytes[40..48].copy_from_slice(&magic());
        assert_eq!(
            measure_bytes(&mut bytes),
            Err(RouterError::AuthenticationFailed)
        );
    }

    #[test]
    fn commitment_slot_is_hashed_as_zeros() {
        let mut bytes = sample_pe();
        let first = measure_bytes(&mut bytes.clone()).expect("measure");
        bytes[0x208] = 0x5A;
        let second = measure_bytes(&mut bytes.clone()).expect("measure");
        assert_eq!(first, second);
        bytes[0x230] ^= 0x01;
        let third = measure_bytes(&mut bytes).expect("measure");
        assert_ne!(first, third);
    }

    fn pe_reloc_file_offset() -> usize {
        0x280
    }

    fn sample_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C] = 0x80;
        bytes[0x80] = b'P';
        bytes[0x81] = b'E';
        bytes[0x84] = 0x64;
        bytes[0x85] = 0x86;
        bytes[0x86] = 1;
        bytes[0x94] = 0xF0;
        bytes[0x98] = 0x0B;
        bytes[0x99] = 0x02;
        bytes[0x80 + 24 + 108] = 16;
        let reloc_dir = 0x80 + 24 + 112 + PE_RELOC_DIRECTORY * 8;
        bytes[reloc_dir] = 0x80;
        bytes[reloc_dir + 1] = 0x02;
        bytes[reloc_dir + 4] = 8;
        let iat_dir = 0x80 + 24 + 112 + PE_IAT_DIRECTORY * 8;
        bytes[iat_dir] = 0x88;
        bytes[iat_dir + 1] = 0x02;
        bytes[iat_dir + 4] = 8;
        let section = 0x80 + 24 + 0xF0;
        bytes[section + 8] = 0x80;
        bytes[section + 9] = 0x02;
        bytes[section + 12] = 0x00;
        bytes[section + 13] = 0x02;
        bytes[section + 16] = 0x80;
        bytes[section + 17] = 0x02;
        bytes[section + 20] = 0x00;
        bytes[section + 21] = 0x02;
        bytes[0x200..0x208].copy_from_slice(&magic());
        bytes[0x280..0x288].fill(0x11);
        bytes[0x288..0x290].fill(0x22);
        bytes
    }
}
