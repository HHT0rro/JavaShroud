use crate::plan::{
    Export, Import, ImportSymbol, InitPlan, ManualMapPlan, MapRegion, MemoryProtection, Relocation,
    RelocationKind, TlsPlan,
};
use crate::{
    checked_range, checked_usize, is_power_of_two, AddressRange, BinaryReader, ImageFormat,
    ParseError, MAX_EXPORTS, MAX_IMPORTS, MAX_RELOCATIONS, MAX_SECTIONS, MAX_STRING_BYTES,
};
use std::collections::BTreeSet;

const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
const PE_MACHINE_AMD64: u16 = 0x8664;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const OPTIONAL_HEADER64_SIZE: usize = 240;
const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_DIRECTORY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_TLS: usize = 9;
const IMAGE_DIRECTORY_DELAY_IMPORT: usize = 13;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const MAX_DIRECTORY_SIZE: u64 = 16 * 1024 * 1024;
const MAX_IMPORT_DESCRIPTORS: usize = 1024;
const MAX_IMPORTS_PER_LIBRARY: usize = 4096;
const MAX_EXPORT_NAMES: usize = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeDataDirectory {
    virtual_address: u32,
    size: u32,
}

impl PeDataDirectory {
    pub const fn new(virtual_address: u32, size: u32) -> Self {
        Self {
            virtual_address,
            size,
        }
    }

    pub const fn virtual_address(self) -> u32 {
        self.virtual_address
    }

    pub const fn size(self) -> u32 {
        self.size
    }

    pub const fn is_present(self) -> bool {
        self.virtual_address != 0 || self.size != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeSection {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
    mapped_size: u64,
}

impl PeSection {
    pub fn name_bytes(&self) -> &[u8; 8] {
        &self.name
    }

    pub const fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    pub const fn virtual_size(&self) -> u32 {
        self.virtual_size
    }

    pub const fn raw_offset(&self) -> u32 {
        self.raw_offset
    }

    pub const fn raw_size(&self) -> u32 {
        self.raw_size
    }

    pub const fn characteristics(&self) -> u32 {
        self.characteristics
    }

    pub const fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    pub const fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub const fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pe64Image {
    image_base: u64,
    image_size: u64,
    size_of_headers: u64,
    section_alignment: u64,
    file_alignment: u64,
    entry_point: u64,
    characteristics: u16,
    sections: Vec<PeSection>,
    directories: [PeDataDirectory; 16],
    relocations: Vec<Relocation>,
    imports: Vec<Import>,
    exports: Vec<Export>,
    tls: TlsPlan,
    init: InitPlan,
}

impl Pe64Image {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 0x40 || bytes[..2] != *b"MZ" {
            return Err(ParseError::Invalid("PE DOS header"));
        }
        let nt_offset = read_u32(bytes, 0x3c)? as u64;
        let nt_end = nt_offset.checked_add(4 + 20).ok_or(ParseError::Overflow)?;
        if nt_end > bytes.len() as u64 {
            return Err(ParseError::OutOfBounds("PE header offset"));
        }
        if read_bytes(bytes, nt_offset, 4)? != PE_SIGNATURE {
            return Err(ParseError::Invalid("PE signature"));
        }
        let file_header = nt_offset.checked_add(4).ok_or(ParseError::Overflow)?;
        let machine = read_u16(bytes, file_header)?;
        if machine != PE_MACHINE_AMD64 {
            return Err(ParseError::Unsupported("PE machine is not AMD64"));
        }
        let section_count = read_u16(bytes, file_header + 2)? as usize;
        if section_count == 0 || section_count > MAX_SECTIONS {
            return Err(ParseError::LimitExceeded("PE section count"));
        }
        let characteristics = read_u16(bytes, file_header + 18)?;
        if characteristics & IMAGE_FILE_DLL == 0 {
            return Err(ParseError::Unsupported("PE image is not a DLL"));
        }
        let optional_size = read_u16(bytes, file_header + 16)? as usize;
        if optional_size < OPTIONAL_HEADER64_SIZE {
            return Err(ParseError::Unsupported("PE optional header is not PE64"));
        }
        let optional_offset = nt_offset.checked_add(24).ok_or(ParseError::Overflow)?;
        let optional_end = optional_offset
            .checked_add(optional_size as u64)
            .ok_or(ParseError::Overflow)?;
        if optional_end > bytes.len() as u64 {
            return Err(ParseError::OutOfBounds("PE optional header"));
        }
        if read_u16(bytes, optional_offset)? != PE32_PLUS_MAGIC {
            return Err(ParseError::Unsupported("PE optional header magic"));
        }
        let image_base = read_u64(bytes, optional_offset + 24)?;
        let section_alignment = read_u32(bytes, optional_offset + 32)? as u64;
        let file_alignment = read_u32(bytes, optional_offset + 36)? as u64;
        let image_size = read_u32(bytes, optional_offset + 56)? as u64;
        let size_of_headers = read_u32(bytes, optional_offset + 60)? as u64;
        let entry_point = read_u32(bytes, optional_offset + 16)? as u64;
        let directory_count = read_u32(bytes, optional_offset + 108)? as usize;
        if directory_count != 16 {
            return Err(ParseError::Unsupported("PE directory count"));
        }
        if image_base == 0 || image_size == 0 || image_size > crate::MAX_IMAGE_SIZE {
            return Err(ParseError::LimitExceeded("PE image size or base"));
        }
        if !is_power_of_two(section_alignment)
            || section_alignment < PAGE_SIZE
            || !is_power_of_two(file_alignment)
            || !(0x200..=0x10000).contains(&file_alignment)
            || file_alignment > section_alignment
        {
            return Err(ParseError::Invalid("PE alignment"));
        }
        if size_of_headers == 0
            || size_of_headers > image_size
            || size_of_headers > bytes.len() as u64
            || size_of_headers % file_alignment != 0
        {
            return Err(ParseError::Invalid("PE header size"));
        }
        let directory_offset = optional_offset
            .checked_add(112)
            .ok_or(ParseError::Overflow)?;
        let directory_bytes = 16usize.checked_mul(8).ok_or(ParseError::Overflow)?;
        if directory_offset + directory_bytes as u64 > optional_end {
            return Err(ParseError::Truncated {
                offset: directory_offset,
                requested: directory_bytes as u64,
                remaining: optional_end.saturating_sub(directory_offset),
            });
        }
        let mut directories = [PeDataDirectory::new(0, 0); 16];
        for (index, directory) in directories.iter_mut().enumerate() {
            let offset = directory_offset + (index * 8) as u64;
            *directory =
                PeDataDirectory::new(read_u32(bytes, offset)?, read_u32(bytes, offset + 4)?);
            if directory.is_present() {
                let size = directory.size as u64;
                if size == 0 || size > MAX_DIRECTORY_SIZE {
                    return Err(ParseError::LimitExceeded("PE directory size"));
                }
                checked_range(directory.virtual_address as u64, size, image_size)?;
            }
        }
        if directories[IMAGE_DIRECTORY_DELAY_IMPORT].is_present() {
            return Err(ParseError::Unsupported("PE delay imports"));
        }
        let section_table = optional_end;
        let section_table_size = (section_count as u64)
            .checked_mul(SECTION_HEADER_SIZE as u64)
            .ok_or(ParseError::Overflow)?;
        if section_table + section_table_size > bytes.len() as u64 {
            return Err(ParseError::Truncated {
                offset: section_table,
                requested: section_table_size,
                remaining: bytes.len() as u64 - section_table,
            });
        }
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let offset = section_table + (index * SECTION_HEADER_SIZE) as u64;
            let name = read_fixed::<8>(bytes, offset)?;
            let virtual_size = read_u32(bytes, offset + 8)?;
            let virtual_address = read_u32(bytes, offset + 12)?;
            let raw_size = read_u32(bytes, offset + 16)?;
            let raw_offset = read_u32(bytes, offset + 20)?;
            let section_characteristics = read_u32(bytes, offset + 36)?;
            let mapped_size = if virtual_size == 0 {
                raw_size as u64
            } else {
                virtual_size as u64
            };
            if mapped_size == 0 || raw_size as u64 > mapped_size {
                return Err(ParseError::Invalid("PE section size"));
            }
            let virtual_range = checked_range(virtual_address as u64, mapped_size, image_size)?;
            if virtual_range.start() < size_of_headers {
                return Err(ParseError::OutOfBounds("PE section overlaps headers"));
            }
            if raw_size != 0 {
                checked_file_range(raw_offset as u64, raw_size as u64, bytes.len())?;
            }
            if section_characteristics & IMAGE_SCN_MEM_WRITE != 0
                && section_characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            {
                return Err(ParseError::WriteExecute);
            }
            sections.push(PeSection {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics: section_characteristics,
                mapped_size,
            });
        }
        validate_section_ranges(&sections)?;
        if entry_point != 0
            && !sections.iter().any(|section| {
                section.is_executable() && section_range(section).contains(entry_point)
            })
        {
            return Err(ParseError::OutOfBounds("PE entry point is not executable"));
        }
        if !sections.iter().any(PeSection::is_executable) {
            return Err(ParseError::Invalid("PE has no executable section"));
        }
        let mut image = Self {
            image_base,
            image_size,
            size_of_headers,
            section_alignment,
            file_alignment,
            entry_point,
            characteristics,
            sections,
            directories,
            relocations: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            tls: TlsPlan::new(Vec::new(), None, 0, 0, 1)?,
            init: InitPlan::new((entry_point != 0).then_some(entry_point), Vec::new())?,
        };
        image.relocations = parse_relocations(bytes, &image)?;
        image.imports = parse_imports(bytes, &image)?;
        image.exports = parse_exports(bytes, &image)?;
        image.tls = parse_tls(bytes, &image)?;
        image.init = InitPlan::new(
            (image.entry_point != 0).then_some(image.entry_point),
            Vec::new(),
        )?;
        Ok(image)
    }

    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    pub const fn image_size(&self) -> u64 {
        self.image_size
    }

    pub const fn size_of_headers(&self) -> u64 {
        self.size_of_headers
    }

    pub const fn section_alignment(&self) -> u64 {
        self.section_alignment
    }

    pub const fn file_alignment(&self) -> u64 {
        self.file_alignment
    }

    pub const fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub const fn characteristics(&self) -> u16 {
        self.characteristics
    }

    pub fn sections(&self) -> &[PeSection] {
        &self.sections
    }

    pub fn directories(&self) -> &[PeDataDirectory; 16] {
        &self.directories
    }

    pub fn map_plan(&self) -> Result<ManualMapPlan, ParseError> {
        let header_protection = MemoryProtection::new(true, false, false)?;
        let header = Some(MapRegion::new(
            0,
            self.size_of_headers,
            0,
            self.size_of_headers,
            header_protection,
        )?);
        let mut regions = Vec::with_capacity(self.sections.len());
        let mut executable_ranges = Vec::new();
        for section in &self.sections {
            let protection = MemoryProtection::new(
                section.characteristics & IMAGE_SCN_MEM_READ != 0,
                section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            )?;
            regions.push(MapRegion::new(
                section.virtual_address as u64,
                section.mapped_size,
                section.raw_offset as u64,
                section.raw_size as u64,
                protection,
            )?);
            if section.is_executable() {
                executable_ranges.push(section_range(section));
            }
        }
        ManualMapPlan::new(
            ImageFormat::Pe64,
            self.image_base,
            self.image_size,
            self.section_alignment,
            header,
            regions,
            self.relocations.clone(),
            self.imports.clone(),
            self.exports.clone(),
            self.tls.clone(),
            self.init.clone(),
            executable_ranges,
        )
    }

    fn directory_file_bytes<'a>(
        &'a self,
        bytes: &'a [u8],
        index: usize,
    ) -> Result<Option<&'a [u8]>, ParseError> {
        let directory = self.directories[index];
        if !directory.is_present() {
            return Ok(None);
        }
        Ok(Some(self.rva_bytes(
            bytes,
            directory.virtual_address as u64,
            directory.size as u64,
        )?))
    }

    fn rva_bytes<'a>(
        &'a self,
        bytes: &'a [u8],
        rva: u64,
        length: u64,
    ) -> Result<&'a [u8], ParseError> {
        let end = rva.checked_add(length).ok_or(ParseError::Overflow)?;
        if end > self.image_size {
            return Err(ParseError::OutOfBounds("PE RVA exceeds image"));
        }
        if end <= self.size_of_headers {
            return file_slice(bytes, rva, length);
        }
        for section in &self.sections {
            let virtual_end = section
                .virtual_address
                .checked_add(section.mapped_size as u32)
                .ok_or(ParseError::Overflow)? as u64;
            let raw_end = (section.raw_offset as u64)
                .checked_add(section.raw_size as u64)
                .ok_or(ParseError::Overflow)?;
            if rva >= section.virtual_address as u64
                && end <= virtual_end
                && end <= section.virtual_address as u64 + section.raw_size as u64
            {
                let offset = section.raw_offset as u64 + (rva - section.virtual_address as u64);
                return file_slice(bytes, offset, length);
            }
            if rva < virtual_end && end > section.virtual_address as u64 && raw_end == 0 {
                return Err(ParseError::OutOfBounds(
                    "PE RVA points into zero-filled section",
                ));
            }
        }
        Err(ParseError::OutOfBounds("PE RVA is not file-backed"))
    }

    fn rva_is_mapped(&self, rva: u64, length: u64) -> bool {
        let end = match rva.checked_add(length) {
            Some(value) => value,
            None => return false,
        };
        self.sections.iter().any(|section| {
            let start = section.virtual_address as u64;
            let section_end = start + section.mapped_size;
            rva >= start && end <= section_end
        })
    }

    fn rva_is_executable(&self, rva: u64, length: u64) -> bool {
        let end = match rva.checked_add(length) {
            Some(value) => value,
            None => return false,
        };
        self.sections.iter().any(|section| {
            section.is_executable()
                && rva >= section.virtual_address as u64
                && end <= section.virtual_address as u64 + section.mapped_size
        })
    }
}

fn validate_section_ranges(sections: &[PeSection]) -> Result<(), ParseError> {
    let mut virtual_ranges: Vec<AddressRange> = sections.iter().map(section_range).collect();
    virtual_ranges.sort_by_key(|range| range.start());
    for pair in virtual_ranges.windows(2) {
        if pair[0].end() > pair[1].start() {
            return Err(ParseError::Invalid("overlapping PE sections"));
        }
    }
    let mut raw_ranges = Vec::new();
    for section in sections {
        if section.raw_size != 0 {
            raw_ranges.push(checked_file_range(
                section.raw_offset as u64,
                section.raw_size as u64,
                usize::MAX,
            )?);
        }
    }
    raw_ranges.sort_by_key(|range| range.start());
    for pair in raw_ranges.windows(2) {
        if pair[0].end() > pair[1].start() {
            return Err(ParseError::Invalid("overlapping PE raw sections"));
        }
    }
    Ok(())
}

fn section_range(section: &PeSection) -> AddressRange {
    AddressRange {
        start: section.virtual_address as u64,
        end: section.virtual_address as u64 + section.mapped_size,
    }
}

fn parse_relocations(bytes: &[u8], image: &Pe64Image) -> Result<Vec<Relocation>, ParseError> {
    let Some(directory) = image.directory_file_bytes(bytes, IMAGE_DIRECTORY_BASERELOC)? else {
        return Ok(Vec::new());
    };
    let mut relocations = Vec::new();
    let mut cursor = BinaryReader::new(directory);
    while cursor.position() < directory.len() {
        if directory.len() - cursor.position() < 8 {
            return Err(ParseError::Truncated {
                offset: cursor.position() as u64,
                requested: 8,
                remaining: (directory.len() - cursor.position()) as u64,
            });
        }
        let page_rva = cursor.read_u32_le()? as u64;
        let block_size = cursor.read_u32_le()? as usize;
        if block_size < 8
            || block_size % 2 != 0
            || block_size > directory.len() - cursor.position() + 8
        {
            return Err(ParseError::Invalid("PE relocation block size"));
        }
        let entry_bytes = block_size - 8;
        let entries = cursor.read_bytes(entry_bytes)?;
        let mut entry_cursor = BinaryReader::new(entries);
        while entry_cursor.position() < entries.len() {
            let raw = entry_cursor.read_u16_le()?;
            let relocation_type = raw >> 12;
            let offset = (raw & 0x0fff) as u64;
            match relocation_type {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => {
                    let target = page_rva.checked_add(offset).ok_or(ParseError::Overflow)?;
                    if !image.rva_is_mapped(target, 8) {
                        return Err(ParseError::OutOfBounds("PE relocation target"));
                    }
                    relocations.push(Relocation::new(
                        RelocationKind::PeDir64,
                        target,
                        None,
                        None,
                        0,
                    ));
                }
                _ => return Err(ParseError::Unsupported("PE relocation type")),
            }
            if relocations.len() > MAX_RELOCATIONS {
                return Err(ParseError::LimitExceeded("PE relocation count"));
            }
        }
    }
    Ok(relocations)
}

fn parse_imports(bytes: &[u8], image: &Pe64Image) -> Result<Vec<Import>, ParseError> {
    let Some(directory) = image.directory_file_bytes(bytes, IMAGE_DIRECTORY_IMPORT)? else {
        return Ok(Vec::new());
    };
    let mut imports = Vec::new();
    let mut descriptor_count = 0usize;
    let mut descriptor_offset = 0u64;
    let mut saw_null = false;
    while descriptor_offset + 20 <= directory.len() as u64 {
        if descriptor_count >= MAX_IMPORT_DESCRIPTORS {
            return Err(ParseError::LimitExceeded("PE import descriptor count"));
        }
        let original_first_thunk = read_u32(directory, descriptor_offset)? as u64;
        let time_date_stamp = read_u32(directory, descriptor_offset + 4)?;
        let forwarder_chain = read_u32(directory, descriptor_offset + 8)?;
        let name_rva = read_u32(directory, descriptor_offset + 12)? as u64;
        let first_thunk = read_u32(directory, descriptor_offset + 16)? as u64;
        descriptor_offset += 20;
        descriptor_count += 1;
        if original_first_thunk == 0
            && time_date_stamp == 0
            && forwarder_chain == 0
            && name_rva == 0
            && first_thunk == 0
        {
            saw_null = true;
            break;
        }
        if first_thunk == 0 || name_rva == 0 {
            return Err(ParseError::Invalid("PE import descriptor"));
        }
        let library = read_ascii_string(image, bytes, name_rva)?;
        let lookup_rva = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        let mut index = 0usize;
        loop {
            if index >= MAX_IMPORTS_PER_LIBRARY {
                return Err(ParseError::LimitExceeded("PE imports per library"));
            }
            let thunk_rva = lookup_rva
                .checked_add((index as u64).checked_mul(8).ok_or(ParseError::Overflow)?)
                .ok_or(ParseError::Overflow)?;
            let thunk = read_u64_rva(image, bytes, thunk_rva)?;
            if thunk == 0 {
                break;
            }
            let symbol = if thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                ImportSymbol::Ordinal((thunk & 0xffff) as u16)
            } else {
                let hint_name_rva = thunk & 0x7fff_ffff_ffff_ffff;
                if !image.rva_is_mapped(hint_name_rva, 2) {
                    return Err(ParseError::OutOfBounds("PE import hint/name"));
                }
                let hint = read_u16_rva(image, bytes, hint_name_rva)?;
                let name = read_ascii_string(image, bytes, hint_name_rva + 2)?;
                ImportSymbol::Name { hint, name }
            };
            let slot = first_thunk
                .checked_add((index as u64).checked_mul(8).ok_or(ParseError::Overflow)?)
                .ok_or(ParseError::Overflow)?;
            if !image.rva_is_mapped(slot, 8) {
                return Err(ParseError::OutOfBounds("PE import address table slot"));
            }
            imports.push(Import::new(Some(library.clone()), symbol, slot));
            if imports.len() > MAX_IMPORTS {
                return Err(ParseError::LimitExceeded("PE import count"));
            }
            index += 1;
        }
    }
    if !saw_null {
        return Err(ParseError::Invalid("PE import directory lacks terminator"));
    }
    Ok(imports)
}

fn parse_exports(bytes: &[u8], image: &Pe64Image) -> Result<Vec<Export>, ParseError> {
    let Some(directory) = image.directory_file_bytes(bytes, IMAGE_DIRECTORY_EXPORT)? else {
        return Ok(Vec::new());
    };
    if directory.len() < 40 {
        return Err(ParseError::Truncated {
            offset: 0,
            requested: 40,
            remaining: directory.len() as u64,
        });
    }
    let base = read_u32(directory, 16)?;
    let function_count = read_u32(directory, 20)? as usize;
    let name_count = read_u32(directory, 24)? as usize;
    let functions_rva = read_u32(directory, 28)? as u64;
    let names_rva = read_u32(directory, 32)? as u64;
    let ordinals_rva = read_u32(directory, 36)? as u64;
    if function_count == 0 || function_count > MAX_EXPORT_NAMES || name_count > function_count {
        return Err(ParseError::LimitExceeded("PE export count"));
    }
    if name_count > MAX_EXPORTS {
        return Err(ParseError::LimitExceeded("PE named export count"));
    }
    let mut exports = Vec::with_capacity(name_count);
    let mut names_seen = BTreeSet::new();
    let directory_start = image.directories[IMAGE_DIRECTORY_EXPORT].virtual_address as u64;
    let directory_end = directory_start + image.directories[IMAGE_DIRECTORY_EXPORT].size as u64;
    for index in 0..name_count {
        let name_rva = read_u32_rva(image, bytes, names_rva + (index as u64) * 4)? as u64;
        let name = read_ascii_string(image, bytes, name_rva)?;
        if !names_seen.insert(name.clone()) {
            return Err(ParseError::Invalid("duplicate PE export name"));
        }
        let ordinal_index = read_u16_rva(image, bytes, ordinals_rva + (index as u64) * 2)? as usize;
        if ordinal_index >= function_count {
            return Err(ParseError::Invalid("PE export ordinal index"));
        }
        let function_rva =
            read_u32_rva(image, bytes, functions_rva + (ordinal_index as u64) * 4)? as u64;
        let forwarder = function_rva >= directory_start && function_rva < directory_end;
        if !forwarder && !image.rva_is_mapped(function_rva, 1) {
            return Err(ParseError::OutOfBounds("PE export address"));
        }
        exports.push(Export::new(
            name,
            base.checked_add(ordinal_index as u32)
                .ok_or(ParseError::Overflow)?,
            function_rva,
            forwarder,
        ));
    }
    Ok(exports)
}

fn parse_tls(bytes: &[u8], image: &Pe64Image) -> Result<TlsPlan, ParseError> {
    let Some(directory) = image.directory_file_bytes(bytes, IMAGE_DIRECTORY_TLS)? else {
        return TlsPlan::new(Vec::new(), None, 0, 0, 1);
    };
    if directory.len() < 40 {
        return Err(ParseError::Truncated {
            offset: 0,
            requested: 40,
            remaining: directory.len() as u64,
        });
    }
    let start_raw = read_u64(directory, 0)?;
    let end_raw = read_u64(directory, 8)?;
    let callbacks_raw = read_u64(directory, 24)?;
    let zero_fill = read_u32(directory, 32)? as u64;
    let characteristics = read_u32(directory, 36)? as u64;
    let template_memory_size = if start_raw == 0 && end_raw == 0 {
        0
    } else {
        if start_raw < image.image_base || end_raw < start_raw {
            return Err(ParseError::Invalid("PE TLS template address"));
        }
        end_raw
            .checked_sub(start_raw)
            .and_then(|size| size.checked_add(zero_fill))
            .ok_or(ParseError::Overflow)?
    };
    if template_memory_size > crate::MAX_IMAGE_SIZE {
        return Err(ParseError::LimitExceeded("PE TLS template"));
    }
    let template_file_size = end_raw.saturating_sub(start_raw);
    let template_file_offset = if template_file_size == 0 {
        None
    } else {
        let start_rva = start_raw
            .checked_sub(image.image_base)
            .ok_or(ParseError::Invalid("PE TLS template base"))?;
        let _ = image.rva_bytes(bytes, start_rva, template_file_size)?;
        Some(image.file_offset_for_rva(start_rva, template_file_size)?)
    };
    let mut callbacks = Vec::new();
    if callbacks_raw != 0 {
        if callbacks_raw < image.image_base {
            return Err(ParseError::Invalid("PE TLS callback table address"));
        }
        let callbacks_rva = callbacks_raw - image.image_base;
        for index in 0..crate::MAX_TLS_CALLBACKS {
            let address = read_u64_rva(image, bytes, callbacks_rva + (index as u64) * 8)?;
            if address == 0 {
                break;
            }
            if address < image.image_base {
                return Err(ParseError::OutOfBounds("PE TLS callback address"));
            }
            let callback_rva = address - image.image_base;
            if !image.rva_is_executable(callback_rva, 1) {
                return Err(ParseError::OutOfBounds("PE TLS callback is not executable"));
            }
            callbacks.push(callback_rva);
            if index + 1 == crate::MAX_TLS_CALLBACKS {
                return Err(ParseError::LimitExceeded("PE TLS callback count"));
            }
        }
    }
    let alignment = if characteristics == 0 {
        1
    } else {
        let raw_alignment = 1u64 << (characteristics & 0xf);
        if raw_alignment == 0 || !is_power_of_two(raw_alignment) {
            return Err(ParseError::Invalid("PE TLS alignment"));
        }
        raw_alignment
    };
    TlsPlan::new(
        callbacks,
        template_file_offset,
        template_file_size,
        template_memory_size,
        alignment,
    )
}

impl Pe64Image {
    fn file_offset_for_rva(&self, rva: u64, length: u64) -> Result<u64, ParseError> {
        if rva.checked_add(length).ok_or(ParseError::Overflow)? <= self.size_of_headers {
            return Ok(rva);
        }
        for section in &self.sections {
            let start = section.virtual_address as u64;
            let raw_end = start
                .checked_add(section.raw_size as u64)
                .ok_or(ParseError::Overflow)?;
            if rva >= start && rva.checked_add(length).ok_or(ParseError::Overflow)? <= raw_end {
                let delta = rva.checked_sub(start).ok_or(ParseError::Overflow)?;
                return section
                    .raw_offset
                    .checked_add(u32::try_from(delta).map_err(|_| ParseError::Overflow)?)
                    .map(u64::from)
                    .ok_or(ParseError::Overflow);
            }
        }
        Err(ParseError::OutOfBounds("PE RVA has no file offset"))
    }
}

fn read_ascii_string(image: &Pe64Image, bytes: &[u8], rva: u64) -> Result<String, ParseError> {
    let mut value = Vec::new();
    for index in 0..MAX_STRING_BYTES {
        let byte = read_u8_rva(image, bytes, rva + index as u64)?;
        if byte == 0 {
            if value.is_empty() {
                return Err(ParseError::Invalid("empty PE string"));
            }
            return String::from_utf8(value)
                .map_err(|_| ParseError::Invalid("PE string is not UTF-8"));
        }
        if !(0x20..=0x7e).contains(&byte) {
            return Err(ParseError::Invalid("PE string is not printable ASCII"));
        }
        value.push(byte);
    }
    Err(ParseError::LimitExceeded("PE string length"))
}

fn read_u8_rva(image: &Pe64Image, bytes: &[u8], rva: u64) -> Result<u8, ParseError> {
    Ok(image.rva_bytes(bytes, rva, 1)?[0])
}

fn read_u16_rva(image: &Pe64Image, bytes: &[u8], rva: u64) -> Result<u16, ParseError> {
    read_u16(image.rva_bytes(bytes, rva, 2)?, 0)
}

fn read_u32_rva(image: &Pe64Image, bytes: &[u8], rva: u64) -> Result<u32, ParseError> {
    read_u32(image.rva_bytes(bytes, rva, 4)?, 0)
}

fn read_u64_rva(image: &Pe64Image, bytes: &[u8], rva: u64) -> Result<u64, ParseError> {
    read_u64(image.rva_bytes(bytes, rva, 8)?, 0)
}

fn checked_file_range(
    offset: u64,
    length: u64,
    bytes_len: usize,
) -> Result<AddressRange, ParseError> {
    let range = AddressRange::new(
        offset,
        offset.checked_add(length).ok_or(ParseError::Overflow)?,
    )?;
    if range.end() > bytes_len as u64 {
        return Err(ParseError::OutOfBounds("file range exceeds input"));
    }
    Ok(range)
}

fn file_slice(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], ParseError> {
    let start = checked_usize(offset)?;
    let len = checked_usize(length)?;
    let end = start.checked_add(len).ok_or(ParseError::Overflow)?;
    if end > bytes.len() {
        return Err(ParseError::OutOfBounds("file slice exceeds input"));
    }
    Ok(&bytes[start..end])
}

fn read_bytes(bytes: &[u8], offset: u64, length: usize) -> Result<&[u8], ParseError> {
    file_slice(bytes, offset, length as u64)
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: u64) -> Result<[u8; N], ParseError> {
    let slice = read_bytes(bytes, offset, N)?;
    let mut output = [0u8; N];
    output.copy_from_slice(slice);
    Ok(output)
}

fn read_u16(bytes: &[u8], offset: u64) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(read_fixed(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: u64) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(read_fixed(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: u64) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(read_fixed(bytes, offset)?))
}

const PAGE_SIZE: u64 = 4096;
