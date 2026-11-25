use crate::plan::{
    Export, Import, ImportSymbol, InitPlan, ManualMapPlan, MapRegion, MemoryProtection, Relocation,
    RelocationKind, TlsPlan,
};
use crate::{
    align_down, align_up, checked_usize, is_power_of_two, AddressRange, BinaryReader, ImageFormat,
    ParseError, MAX_DYNAMIC_ENTRIES, MAX_EXPORTS, MAX_IMPORTS, MAX_RELOCATIONS, MAX_SEGMENTS,
    MAX_STRING_BYTES, PAGE_SIZE,
};
use std::collections::{BTreeMap, BTreeSet};

const ELF_CLASS64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ELF_VERSION_CURRENT: u8 = 1;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 0x3e;
const ELF_HEADER_SIZE: u16 = 64;
const ELF_PROGRAM_HEADER_SIZE: u16 = 56;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_TLS: u32 = 7;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_TEXTREL: i64 = 22;
const DT_JMPREL: i64 = 23;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTREL: i64 = 20;
const DT_INIT_ARRAY: i64 = 25;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_GNU_HASH: i64 = 0x6ffffef5;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_RELR: i64 = 36;
const DT_RELR_ALT: i64 = 0x6ffffdf0;
const R_X86_64_64: u32 = 1;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;
const R_X86_64_DTPMOD64: u32 = 16;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;
const SHN_UNDEF: u16 = 0;
const MAX_DYNAMIC_STRING_BYTES: u64 = 16 * 1024 * 1024;
const MAX_NEEDED_LIBRARIES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Elf64Segment {
    segment_type: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

impl Elf64Segment {
    pub const fn segment_type(&self) -> u32 {
        self.segment_type
    }

    pub const fn flags(&self) -> u32 {
        self.flags
    }

    pub const fn file_offset(&self) -> u64 {
        self.file_offset
    }

    pub const fn virtual_address(&self) -> u64 {
        self.virtual_address
    }

    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    pub const fn memory_size(&self) -> u64 {
        self.memory_size
    }

    pub const fn alignment(&self) -> u64 {
        self.alignment
    }

    pub const fn is_load(&self) -> bool {
        self.segment_type == PT_LOAD
    }

    pub const fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfDynamicEntry {
    tag: i64,
    value: u64,
}

impl ElfDynamicEntry {
    pub const fn tag(&self) -> i64 {
        self.tag
    }

    pub const fn value(&self) -> u64 {
        self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ElfSymbol {
    name: String,
    value: u64,
    size: u64,
    binding: u8,
    symbol_type: u8,
    section_index: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Elf64Image {
    image_low: u64,
    image_high: u64,
    entry_point: u64,
    segments: Vec<Elf64Segment>,
    dynamic: Vec<ElfDynamicEntry>,
    needed: Vec<String>,
    symbols: Vec<ElfSymbol>,
    relocations: Vec<Relocation>,
    imports: Vec<Import>,
    exports: Vec<Export>,
    tls: TlsPlan,
    init: InitPlan,
}

impl Elf64Image {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < ELF_HEADER_SIZE as usize || bytes[..4] != *b"\x7fELF" {
            return Err(ParseError::Invalid("ELF header"));
        }
        if bytes[4] != ELF_CLASS64
            || bytes[5] != ELF_DATA_LSB
            || bytes[6] != ELF_VERSION_CURRENT
            || bytes[7] != 0
        {
            return Err(ParseError::Unsupported("ELF class, endianness, or ABI"));
        }
        let e_type = read_u16(bytes, 16)?;
        let machine = read_u16(bytes, 18)?;
        let version = read_u32(bytes, 20)?;
        let entry_point = read_u64(bytes, 24)?;
        let program_offset = read_u64(bytes, 32)?;
        let header_size = read_u16(bytes, 52)?;
        let program_entry_size = read_u16(bytes, 54)?;
        let program_count = read_u16(bytes, 56)? as usize;
        if e_type != ET_DYN || machine != EM_X86_64 {
            return Err(ParseError::Unsupported("ELF is not x86_64 ET_DYN"));
        }
        if version != 1
            || header_size != ELF_HEADER_SIZE
            || program_entry_size != ELF_PROGRAM_HEADER_SIZE
            || program_count == 0
            || program_count > MAX_SEGMENTS
        {
            return Err(ParseError::Invalid("ELF header geometry"));
        }
        let program_table_size = (program_count as u64)
            .checked_mul(ELF_PROGRAM_HEADER_SIZE as u64)
            .ok_or(ParseError::Overflow)?;
        checked_file_range(program_offset, program_table_size, bytes.len())?;
        let mut segments = Vec::with_capacity(program_count);
        let mut load_ranges = Vec::new();
        let mut dynamic_segment = None;
        let mut tls_segment = None;
        for index in 0..program_count {
            let offset = program_offset + (index as u64) * ELF_PROGRAM_HEADER_SIZE as u64;
            let segment_type = read_u32(bytes, offset)?;
            let flags = read_u32(bytes, offset + 4)?;
            let file_offset = read_u64(bytes, offset + 8)?;
            let virtual_address = read_u64(bytes, offset + 16)?;
            let file_size = read_u64(bytes, offset + 32)?;
            let memory_size = read_u64(bytes, offset + 40)?;
            let alignment = read_u64(bytes, offset + 48)?;
            if segment_type == PT_LOAD {
                if memory_size == 0 || file_size > memory_size {
                    return Err(ParseError::Invalid("ELF PT_LOAD size"));
                }
                checked_file_range(file_offset, file_size, bytes.len())?;
                if flags & PF_W != 0 && flags & PF_X != 0 {
                    return Err(ParseError::WriteExecute);
                }
                if alignment > 1
                    && (!is_power_of_two(alignment)
                        || file_offset % alignment != virtual_address % alignment)
                {
                    return Err(ParseError::Invalid("ELF PT_LOAD alignment"));
                }
                let end = virtual_address
                    .checked_add(memory_size)
                    .ok_or(ParseError::Overflow)?;
                load_ranges.push(AddressRange::new(virtual_address, end)?);
            } else if segment_type == PT_DYNAMIC {
                if dynamic_segment.is_some() {
                    return Err(ParseError::Invalid("multiple ELF PT_DYNAMIC segments"));
                }
                checked_file_range(file_offset, file_size, bytes.len())?;
                if file_size == 0 || file_size % 16 != 0 {
                    return Err(ParseError::Invalid("ELF dynamic segment size"));
                }
                dynamic_segment = Some(index);
            } else if segment_type == PT_TLS {
                if tls_segment.is_some() {
                    return Err(ParseError::Invalid("multiple ELF PT_TLS segments"));
                }
                if file_size > memory_size {
                    return Err(ParseError::Invalid("ELF TLS template size"));
                }
                checked_file_range(file_offset, file_size, bytes.len())?;
                if alignment > 1 && !is_power_of_two(alignment) {
                    return Err(ParseError::Invalid("ELF TLS alignment"));
                }
                tls_segment = Some(index);
            }
            segments.push(Elf64Segment {
                segment_type,
                flags,
                file_offset,
                virtual_address,
                file_size,
                memory_size,
                alignment,
            });
        }
        if load_ranges.is_empty()
            || !segments
                .iter()
                .any(|segment| segment.is_load() && segment.is_executable())
        {
            return Err(ParseError::Invalid(
                "ELF load or executable segment missing",
            ));
        }
        load_ranges.sort_by_key(|range| range.start());
        for pair in load_ranges.windows(2) {
            if pair[0].end() > pair[1].start() {
                return Err(ParseError::Invalid("overlapping ELF PT_LOAD segments"));
            }
        }
        let lowest = match load_ranges.first() {
            Some(range) => range.start(),
            None => return Err(ParseError::Invalid("ELF load segment missing")),
        };
        let highest = match load_ranges.last() {
            Some(range) => range.end(),
            None => return Err(ParseError::Invalid("ELF load segment missing")),
        };
        let image_low = align_down(lowest, PAGE_SIZE);
        let image_high = align_up(highest, PAGE_SIZE)?;
        let image_size = image_high
            .checked_sub(image_low)
            .ok_or(ParseError::Overflow)?;
        if image_size == 0 || image_size > crate::MAX_IMAGE_SIZE {
            return Err(ParseError::LimitExceeded("ELF mapped image size"));
        }
        if entry_point != 0
            && !segments.iter().any(|segment| {
                segment.is_load()
                    && segment.is_executable()
                    && entry_point >= segment.virtual_address
                    && entry_point < segment.virtual_address + segment.memory_size
            })
        {
            return Err(ParseError::OutOfBounds("ELF entry point is not executable"));
        }
        let dynamic_index = dynamic_segment.ok_or(ParseError::Invalid("ELF PT_DYNAMIC missing"))?;
        let mut image = Self {
            image_low,
            image_high,
            entry_point,
            segments,
            dynamic: Vec::new(),
            needed: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            tls: TlsPlan::new(Vec::new(), None, 0, 0, 1)?,
            init: InitPlan::new(None, Vec::new())?,
        };
        image.dynamic = parse_dynamic(bytes, &image, dynamic_index)?;
        let tags = DynamicTags::from_entries(&image.dynamic)?;
        image.needed = parse_needed(bytes, &image, &tags)?;
        image.symbols = parse_symbols(bytes, &image, &tags)?;
        let (relocations, imports) = parse_relocations(bytes, &image, &tags)?;
        image.relocations = relocations;
        image.imports = imports;
        image.exports = parse_exports(&image)?;
        image.tls = parse_tls(&image, tls_segment)?;
        image.init = parse_initializers(bytes, &image, &tags)?;
        Ok(image)
    }

    pub const fn image_low(&self) -> u64 {
        self.image_low
    }

    pub const fn image_high(&self) -> u64 {
        self.image_high
    }

    pub const fn image_size(&self) -> u64 {
        self.image_high - self.image_low
    }

    pub const fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn segments(&self) -> &[Elf64Segment] {
        &self.segments
    }

    pub fn dynamic(&self) -> &[ElfDynamicEntry] {
        &self.dynamic
    }

    pub fn needed_libraries(&self) -> &[String] {
        &self.needed
    }

    pub fn map_plan(&self) -> Result<ManualMapPlan, ParseError> {
        let mut regions = Vec::new();
        let mut executable_ranges = Vec::new();
        for segment in self.segments.iter().filter(|segment| segment.is_load()) {
            let protection = MemoryProtection::new(
                segment.flags & PF_R != 0,
                segment.flags & PF_W != 0,
                segment.flags & PF_X != 0,
            )?;
            let virtual_address = segment
                .virtual_address
                .checked_sub(self.image_low)
                .ok_or(ParseError::Overflow)?;
            regions.push(MapRegion::new(
                virtual_address,
                segment.memory_size,
                segment.file_offset,
                segment.file_size,
                protection,
            )?);
            if segment.is_executable() {
                let start = virtual_address;
                let end = start
                    .checked_add(segment.memory_size)
                    .ok_or(ParseError::Overflow)?;
                executable_ranges.push(AddressRange::new(start, end)?);
            }
        }
        executable_ranges.sort_by_key(|range| range.start());
        ManualMapPlan::new(
            ImageFormat::Elf64,
            self.image_low,
            self.image_size(),
            PAGE_SIZE,
            None,
            regions,
            self.relocations.clone(),
            self.imports.clone(),
            self.exports.clone(),
            self.tls.clone(),
            self.init.clone(),
            executable_ranges,
        )
    }

    fn vaddr_bytes<'a>(
        &'a self,
        bytes: &'a [u8],
        address: u64,
        length: u64,
    ) -> Result<&'a [u8], ParseError> {
        let end = address.checked_add(length).ok_or(ParseError::Overflow)?;
        for segment in self.segments.iter().filter(|segment| segment.is_load()) {
            let segment_end = segment
                .virtual_address
                .checked_add(segment.file_size)
                .ok_or(ParseError::Overflow)?;
            if address >= segment.virtual_address && end <= segment_end {
                let offset = segment
                    .file_offset
                    .checked_add(address - segment.virtual_address)
                    .ok_or(ParseError::Overflow)?;
                return file_slice(bytes, offset, length);
            }
        }
        Err(ParseError::OutOfBounds(
            "ELF virtual range is not file-backed",
        ))
    }

    fn vaddr_is_mapped(&self, address: u64, length: u64) -> bool {
        let end = match address.checked_add(length) {
            Some(value) => value,
            None => return false,
        };
        self.segments
            .iter()
            .filter(|segment| segment.is_load())
            .any(|segment| {
                address >= segment.virtual_address
                    && end <= segment.virtual_address + segment.memory_size
            })
    }

    fn vaddr_is_executable(&self, address: u64, length: u64) -> bool {
        let end = match address.checked_add(length) {
            Some(value) => value,
            None => return false,
        };
        self.segments
            .iter()
            .filter(|segment| segment.is_load())
            .any(|segment| {
                segment.is_executable()
                    && address >= segment.virtual_address
                    && end <= segment.virtual_address + segment.memory_size
            })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DynamicTags {
    values: BTreeMap<i64, u64>,
    needed: Vec<u64>,
}

impl DynamicTags {
    fn from_entries(entries: &[ElfDynamicEntry]) -> Result<Self, ParseError> {
        let mut values = BTreeMap::new();
        let mut needed = Vec::new();
        for entry in entries {
            match entry.tag {
                DT_NULL => break,
                DT_NEEDED => {
                    if needed.len() >= MAX_NEEDED_LIBRARIES {
                        return Err(ParseError::LimitExceeded("ELF dependency count"));
                    }
                    needed.push(entry.value);
                }
                DT_TEXTREL | DT_REL | DT_RELSZ | DT_RELENT | DT_RELR | DT_RELR_ALT
                | DT_PREINIT_ARRAY => {
                    return Err(ParseError::Unsupported(
                        "ELF relocation or initializer format",
                    ));
                }
                _ => {
                    if values.insert(entry.tag, entry.value).is_some() {
                        return Err(ParseError::Invalid("duplicate ELF dynamic tag"));
                    }
                }
            }
        }
        if values.contains_key(&DT_PLTREL) && values.get(&DT_PLTREL) != Some(&7) {
            return Err(ParseError::Unsupported("ELF PLT relocation format"));
        }
        if values.get(&DT_SYMENT).copied().unwrap_or(24) != 24
            || values.get(&DT_RELAENT).copied().unwrap_or(24) != 24
        {
            return Err(ParseError::Unsupported("ELF dynamic entry width"));
        }
        if values.contains_key(&DT_RELASZ) != values.contains_key(&DT_RELA)
            && values.get(&DT_RELASZ).copied().unwrap_or(0) != 0
        {
            return Err(ParseError::Invalid("ELF RELA table declaration"));
        }
        if values.contains_key(&DT_JMPREL) != values.contains_key(&DT_PLTRELSZ)
            && values.get(&DT_PLTRELSZ).copied().unwrap_or(0) != 0
        {
            return Err(ParseError::Invalid("ELF PLT RELA declaration"));
        }
        Ok(Self { values, needed })
    }

    fn get(&self, tag: i64) -> Option<u64> {
        self.values.get(&tag).copied()
    }
}

fn parse_dynamic(
    bytes: &[u8],
    image: &Elf64Image,
    dynamic_index: usize,
) -> Result<Vec<ElfDynamicEntry>, ParseError> {
    let segment = &image.segments[dynamic_index];
    let dynamic_bytes = file_slice(bytes, segment.file_offset, segment.file_size)?;
    let mut cursor = BinaryReader::new(dynamic_bytes);
    let mut entries = Vec::new();
    let mut found_null = false;
    for _ in 0..MAX_DYNAMIC_ENTRIES {
        if cursor.position() >= dynamic_bytes.len() {
            break;
        }
        let tag = cursor.read_i64_le()?;
        let value = cursor.read_u64_le()?;
        entries.push(ElfDynamicEntry { tag, value });
        if tag == DT_NULL {
            found_null = true;
            break;
        }
    }
    if !found_null {
        return Err(ParseError::Invalid("ELF dynamic table lacks DT_NULL"));
    }
    Ok(entries)
}

fn parse_needed(
    bytes: &[u8],
    image: &Elf64Image,
    tags: &DynamicTags,
) -> Result<Vec<String>, ParseError> {
    if tags.needed.is_empty() {
        return Ok(Vec::new());
    }
    let strtab = tags
        .get(DT_STRTAB)
        .ok_or(ParseError::Invalid("ELF string table missing"))?;
    let strsz = tags
        .get(DT_STRSZ)
        .ok_or(ParseError::Invalid("ELF string table size missing"))?;
    if strsz == 0 || strsz > MAX_DYNAMIC_STRING_BYTES {
        return Err(ParseError::LimitExceeded("ELF string table size"));
    }
    let _ = image.vaddr_bytes(bytes, strtab, strsz)?;
    tags.needed
        .iter()
        .map(|offset| read_elf_string(bytes, image, strtab, strsz, *offset))
        .collect()
}

fn parse_symbols(
    bytes: &[u8],
    image: &Elf64Image,
    tags: &DynamicTags,
) -> Result<Vec<ElfSymbol>, ParseError> {
    let Some(symtab) = tags.get(DT_SYMTAB) else {
        if tags.get(DT_RELA).is_some() || tags.get(DT_JMPREL).is_some() {
            return Err(ParseError::Invalid("ELF symbol table missing"));
        }
        return Ok(Vec::new());
    };
    let strtab = tags
        .get(DT_STRTAB)
        .ok_or(ParseError::Invalid("ELF string table missing"))?;
    let strsz = tags
        .get(DT_STRSZ)
        .ok_or(ParseError::Invalid("ELF string table size missing"))?;
    if strsz == 0 || strsz > MAX_DYNAMIC_STRING_BYTES {
        return Err(ParseError::LimitExceeded("ELF string table size"));
    }
    let _ = image.vaddr_bytes(bytes, strtab, strsz)?;
    let count = symbol_count(bytes, image, tags)?;
    if count == 0 || count > crate::MAX_EXPORTS.max(MAX_IMPORTS) {
        return Err(ParseError::LimitExceeded("ELF symbol count"));
    }
    let mut symbols = Vec::with_capacity(count);
    for index in 0..count {
        let entry_address = symtab
            .checked_add((index as u64).checked_mul(24).ok_or(ParseError::Overflow)?)
            .ok_or(ParseError::Overflow)?;
        let entry = image.vaddr_bytes(bytes, entry_address, 24)?;
        let name_offset = read_u32(entry, 0)? as u64;
        let info = read_u8(entry, 4)?;
        let section_index = read_u16(entry, 6)?;
        let value = read_u64(entry, 8)?;
        let size = read_u64(entry, 16)?;
        let symbol_type = info & 0x0f;
        let binding = info >> 4;
        if symbol_type == STT_GNU_IFUNC {
            return Err(ParseError::Unsupported("ELF GNU indirect functions"));
        }
        let name = if name_offset == 0 {
            String::new()
        } else {
            read_elf_string(bytes, image, strtab, strsz, name_offset)?
        };
        if section_index != SHN_UNDEF && value != 0 && !image.vaddr_is_mapped(value, 1) {
            return Err(ParseError::OutOfBounds("ELF symbol address"));
        }
        symbols.push(ElfSymbol {
            name,
            value,
            size,
            binding,
            symbol_type,
            section_index,
        });
    }
    Ok(symbols)
}

fn symbol_count(bytes: &[u8], image: &Elf64Image, tags: &DynamicTags) -> Result<usize, ParseError> {
    if let Some(hash) = tags.get(DT_HASH) {
        let header = image.vaddr_bytes(bytes, hash, 8)?;
        let bucket_count = read_u32(header, 0)? as u64;
        let chain_count = read_u32(header, 4)? as usize;
        if chain_count == 0 || chain_count > 65536 || bucket_count > 65536 {
            return Err(ParseError::LimitExceeded("ELF SysV hash size"));
        }
        let entries = 2u64
            .checked_add(bucket_count)
            .and_then(|value| value.checked_add(chain_count as u64))
            .ok_or(ParseError::Overflow)?;
        let _ = image.vaddr_bytes(
            bytes,
            hash,
            entries.checked_mul(4).ok_or(ParseError::Overflow)?,
        )?;
        return Ok(chain_count);
    }
    let gnu_hash = tags
        .get(DT_GNU_HASH)
        .ok_or(ParseError::Invalid("ELF symbol hash missing"))?;
    let header = image.vaddr_bytes(bytes, gnu_hash, 16)?;
    let bucket_count = read_u32(header, 0)? as u64;
    let symbol_offset = read_u32(header, 4)? as usize;
    let bloom_count = read_u32(header, 8)? as u64;
    let _bloom_shift = read_u32(header, 12)?;
    if bucket_count == 0 || bucket_count > 65536 || bloom_count == 0 || bloom_count > 65536 {
        return Err(ParseError::LimitExceeded("ELF GNU hash size"));
    }
    let buckets_address = gnu_hash
        .checked_add(16)
        .and_then(|value| value.checked_add(bloom_count.checked_mul(8)?))
        .ok_or(ParseError::Overflow)?;
    let buckets = image.vaddr_bytes(bytes, buckets_address, bucket_count * 4)?;
    let chains_address = buckets_address
        .checked_add(bucket_count * 4)
        .ok_or(ParseError::Overflow)?;
    let mut maximum = symbol_offset;
    for index in 0..bucket_count as usize {
        let bucket = read_u32(buckets, (index * 4) as u64)? as usize;
        if bucket < symbol_offset {
            continue;
        }
        let mut symbol_index = bucket;
        for _ in 0..65536usize {
            let chain_offset = (symbol_index - symbol_offset)
                .checked_mul(4)
                .ok_or(ParseError::Overflow)? as u64;
            let chain = image.vaddr_bytes(bytes, chains_address + chain_offset, 4)?;
            let value = read_u32(chain, 0)?;
            maximum = maximum.max(symbol_index + 1);
            if value & 1 != 0 {
                break;
            }
            symbol_index = symbol_index.checked_add(1).ok_or(ParseError::Overflow)?;
        }
    }
    if maximum == 0 || maximum > 65536 {
        return Err(ParseError::LimitExceeded("ELF GNU symbol count"));
    }
    Ok(maximum)
}

fn parse_relocations(
    bytes: &[u8],
    image: &Elf64Image,
    tags: &DynamicTags,
) -> Result<(Vec<Relocation>, Vec<Import>), ParseError> {
    let mut relocations = Vec::new();
    let mut imports = Vec::new();
    let mut seen_targets = BTreeSet::new();
    if let Some(rela) = tags.get(DT_RELA) {
        let size = tags
            .get(DT_RELASZ)
            .ok_or(ParseError::Invalid("ELF RELA size missing"))?;
        parse_rela_table(
            bytes,
            image,
            rela,
            size,
            &mut relocations,
            &mut imports,
            &mut seen_targets,
        )?;
    }
    if let Some(jmprel) = tags.get(DT_JMPREL) {
        let size = tags
            .get(DT_PLTRELSZ)
            .ok_or(ParseError::Invalid("ELF PLT RELA size missing"))?;
        parse_rela_table(
            bytes,
            image,
            jmprel,
            size,
            &mut relocations,
            &mut imports,
            &mut seen_targets,
        )?;
    }
    Ok((relocations, imports))
}

fn parse_rela_table(
    bytes: &[u8],
    image: &Elf64Image,
    address: u64,
    size: u64,
    relocations: &mut Vec<Relocation>,
    imports: &mut Vec<Import>,
    seen_targets: &mut BTreeSet<(u64, u32)>,
) -> Result<(), ParseError> {
    if size == 0 {
        return Ok(());
    }
    if size % 24 != 0 || size / 24 > crate::MAX_RELOCATIONS as u64 {
        return Err(ParseError::LimitExceeded("ELF RELA table"));
    }
    let _ = image.vaddr_bytes(bytes, address, size)?;
    for index in 0..(size / 24) {
        let entry_address = address + index * 24;
        let entry = image.vaddr_bytes(bytes, entry_address, 24)?;
        let target = read_u64(entry, 0)?;
        let info = read_u64(entry, 8)?;
        let addend = read_i64(entry, 16)?;
        let symbol_index = (info >> 32) as usize;
        let relocation_type = info as u32;
        if !image.vaddr_is_mapped(target, 8) {
            return Err(ParseError::OutOfBounds("ELF relocation target"));
        }
        if !seen_targets.insert((target, relocation_type)) {
            return Err(ParseError::Invalid("duplicate ELF relocation target"));
        }
        let mut symbol_value = None;
        let symbol = match relocation_type {
            R_X86_64_RELATIVE => {
                if symbol_index != 0 {
                    return Err(ParseError::Invalid("ELF RELATIVE relocation symbol"));
                }
                None
            }
            R_X86_64_DTPMOD64 => {
                if symbol_index >= image.symbols.len() {
                    return Err(ParseError::OutOfBounds("ELF TLS relocation symbol"));
                }
                None
            }
            R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let symbol = image
                    .symbols
                    .get(symbol_index)
                    .ok_or(ParseError::OutOfBounds("ELF relocation symbol"))?;
                if symbol.section_index == SHN_UNDEF {
                    if symbol.name.is_empty() {
                        return Err(ParseError::Invalid("ELF undefined symbol has no name"));
                    }
                    let import_symbol = ImportSymbol::Name {
                        hint: 0,
                        name: symbol.name.clone(),
                    };
                    let slot = target
                        .checked_sub(image.image_low)
                        .ok_or(ParseError::Overflow)?;
                    imports.push(Import::new(None, import_symbol.clone(), slot));
                    if imports.len() > MAX_IMPORTS {
                        return Err(ParseError::LimitExceeded("ELF import count"));
                    }
                    Some(import_symbol)
                } else {
                    symbol_value = Some(
                        symbol
                            .value
                            .checked_sub(image.image_low)
                            .ok_or(ParseError::Overflow)?,
                    );
                    None
                }
            }
            _ => return Err(ParseError::Unsupported("ELF relocation type")),
        };
        let kind = match relocation_type {
            R_X86_64_RELATIVE => RelocationKind::ElfRelative,
            R_X86_64_DTPMOD64 => RelocationKind::ElfDtpMod64,
            R_X86_64_64 => RelocationKind::ElfAbsolute,
            R_X86_64_GLOB_DAT => RelocationKind::ElfGlobDat,
            R_X86_64_JUMP_SLOT => RelocationKind::ElfJumpSlot,
            _ => return Err(ParseError::Unsupported("ELF relocation type")),
        };
        relocations.push(Relocation::new(
            kind,
            target
                .checked_sub(image.image_low)
                .ok_or(ParseError::Overflow)?,
            symbol,
            symbol_value,
            addend,
        ));
        if relocations.len() > MAX_RELOCATIONS {
            return Err(ParseError::LimitExceeded("ELF relocation count"));
        }
    }
    Ok(())
}

fn parse_exports(image: &Elf64Image) -> Result<Vec<Export>, ParseError> {
    let mut exports = Vec::new();
    let mut seen = BTreeSet::new();
    for (ordinal, symbol) in image.symbols.iter().enumerate() {
        if symbol.section_index == SHN_UNDEF
            || symbol.name.is_empty()
            || !matches!(symbol.binding, STB_GLOBAL | STB_WEAK)
            || symbol.value == 0
        {
            continue;
        }
        if !seen.insert(symbol.name.clone()) {
            return Err(ParseError::Invalid("duplicate ELF export name"));
        }
        let address = symbol
            .value
            .checked_sub(image.image_low)
            .ok_or(ParseError::Overflow)?;
        exports.push(Export::new(
            symbol.name.clone(),
            ordinal as u32,
            address,
            false,
        ));
    }
    if exports.len() > MAX_EXPORTS {
        return Err(ParseError::LimitExceeded("ELF export count"));
    }
    Ok(exports)
}

fn parse_tls(image: &Elf64Image, tls_index: Option<usize>) -> Result<TlsPlan, ParseError> {
    let Some(index) = tls_index else {
        return TlsPlan::new(Vec::new(), None, 0, 0, 1);
    };
    let segment = &image.segments[index];
    let alignment = if segment.alignment <= 1 {
        1
    } else {
        segment.alignment
    };
    TlsPlan::new(
        Vec::new(),
        (segment.file_size != 0).then_some(segment.file_offset),
        segment.file_size,
        segment.memory_size,
        alignment,
    )
}

fn parse_initializers(
    bytes: &[u8],
    image: &Elf64Image,
    tags: &DynamicTags,
) -> Result<InitPlan, ParseError> {
    let entry_point = tags.get(DT_INIT).map(|address| {
        if address == 0 {
            return Err(ParseError::Invalid("ELF DT_INIT is zero"));
        }
        if !image.vaddr_is_executable(address, 1) {
            return Err(ParseError::OutOfBounds("ELF DT_INIT is not executable"));
        }
        Ok(address - image.image_low)
    });
    let entry_point = match entry_point {
        Some(value) => Some(value?),
        None => None,
    };
    let mut init_functions = Vec::new();
    if let Some(array) = tags.get(DT_INIT_ARRAY) {
        let size = tags
            .get(DT_INIT_ARRAYSZ)
            .ok_or(ParseError::Invalid("ELF init array size missing"))?;
        if size % 8 != 0 || size / 8 > crate::MAX_INIT_FUNCTIONS as u64 {
            return Err(ParseError::LimitExceeded("ELF init array"));
        }
        for index in 0..(size / 8) {
            let address = read_u64(image.vaddr_bytes(bytes, array + index * 8, 8)?, 0)?;
            if address == 0 {
                continue;
            }
            if !image.vaddr_is_executable(address, 1) {
                return Err(ParseError::OutOfBounds("ELF init array entry"));
            }
            init_functions.push(address - image.image_low);
        }
    } else if tags.get(DT_INIT_ARRAYSZ).unwrap_or(0) != 0 {
        return Err(ParseError::Invalid("ELF init array declaration"));
    }
    InitPlan::new(entry_point, init_functions)
}

fn read_elf_string(
    bytes: &[u8],
    image: &Elf64Image,
    strtab: u64,
    strsz: u64,
    offset: u64,
) -> Result<String, ParseError> {
    if offset >= strsz {
        return Err(ParseError::OutOfBounds("ELF string offset"));
    }
    let mut output = Vec::new();
    for index in 0..MAX_STRING_BYTES {
        let relative = offset
            .checked_add(index as u64)
            .ok_or(ParseError::Overflow)?;
        if relative >= strsz {
            return Err(ParseError::Invalid("unterminated ELF string"));
        }
        let byte = image.vaddr_bytes(bytes, strtab + relative, 1)?[0];
        if byte == 0 {
            return String::from_utf8(output)
                .map_err(|_| ParseError::Invalid("ELF string is not UTF-8"));
        }
        if !(0x20..=0x7e).contains(&byte) {
            return Err(ParseError::Invalid("ELF string is not printable ASCII"));
        }
        output.push(byte);
    }
    Err(ParseError::LimitExceeded("ELF string length"))
}

fn checked_file_range(
    offset: u64,
    length: u64,
    bytes_len: usize,
) -> Result<AddressRange, ParseError> {
    let end = offset.checked_add(length).ok_or(ParseError::Overflow)?;
    if end > bytes_len as u64 {
        return Err(ParseError::OutOfBounds("ELF file range"));
    }
    AddressRange::new(offset, end)
}

fn file_slice(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], ParseError> {
    let start = checked_usize(offset)?;
    let length = checked_usize(length)?;
    let end = start.checked_add(length).ok_or(ParseError::Overflow)?;
    if end > bytes.len() {
        return Err(ParseError::OutOfBounds("ELF file slice"));
    }
    Ok(&bytes[start..end])
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: u64) -> Result<[u8; N], ParseError> {
    let slice = file_slice(bytes, offset, N as u64)?;
    let mut output = [0u8; N];
    output.copy_from_slice(slice);
    Ok(output)
}

fn read_u8(bytes: &[u8], offset: u64) -> Result<u8, ParseError> {
    Ok(file_slice(bytes, offset, 1)?[0])
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

fn read_i64(bytes: &[u8], offset: u64) -> Result<i64, ParseError> {
    Ok(i64::from_le_bytes(read_fixed(bytes, offset)?))
}
