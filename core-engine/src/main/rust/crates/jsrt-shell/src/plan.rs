use crate::{AddressRange, ParseError, R1_REQUIRED_EXPORTS};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageFormat {
    Pe64,
    Elf64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryProtection {
    pub const fn new(read: bool, write: bool, execute: bool) -> Result<Self, ParseError> {
        if write && execute {
            return Err(ParseError::WriteExecute);
        }
        Ok(Self {
            read,
            write,
            execute,
        })
    }

    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapRegion {
    virtual_address: u64,
    memory_size: u64,
    file_offset: u64,
    file_size: u64,
    protection: MemoryProtection,
}

impl MapRegion {
    pub fn new(
        virtual_address: u64,
        memory_size: u64,
        file_offset: u64,
        file_size: u64,
        protection: MemoryProtection,
    ) -> Result<Self, ParseError> {
        if memory_size == 0 || file_size > memory_size {
            return Err(ParseError::Invalid("invalid mapping region size"));
        }
        virtual_address
            .checked_add(memory_size)
            .ok_or(ParseError::Overflow)?;
        file_offset
            .checked_add(file_size)
            .ok_or(ParseError::Overflow)?;
        Ok(Self {
            virtual_address,
            memory_size,
            file_offset,
            file_size,
            protection,
        })
    }

    pub const fn virtual_address(&self) -> u64 {
        self.virtual_address
    }

    pub const fn memory_size(&self) -> u64 {
        self.memory_size
    }

    pub const fn file_offset(&self) -> u64 {
        self.file_offset
    }

    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    pub const fn protection(&self) -> MemoryProtection {
        self.protection
    }

    pub const fn virtual_range(&self) -> AddressRange {
        AddressRange {
            start: self.virtual_address,
            end: self.virtual_address + self.memory_size,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelocationKind {
    PeAbsolute,
    PeDir64,
    ElfRelative,
    ElfAbsolute,
    ElfGlobDat,
    ElfJumpSlot,
    ElfDtpMod64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relocation {
    kind: RelocationKind,
    target: u64,
    symbol: Option<ImportSymbol>,
    symbol_value: Option<u64>,
    addend: i64,
}

impl Relocation {
    pub(crate) fn new(
        kind: RelocationKind,
        target: u64,
        symbol: Option<ImportSymbol>,
        symbol_value: Option<u64>,
        addend: i64,
    ) -> Self {
        Self {
            kind,
            target,
            symbol,
            symbol_value,
            addend,
        }
    }

    pub const fn kind(&self) -> &RelocationKind {
        &self.kind
    }

    pub const fn target(&self) -> u64 {
        self.target
    }

    pub const fn symbol(&self) -> Option<&ImportSymbol> {
        self.symbol.as_ref()
    }

    pub const fn symbol_value(&self) -> Option<u64> {
        self.symbol_value
    }

    pub const fn addend(&self) -> i64 {
        self.addend
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImportSymbol {
    Name { hint: u16, name: String },
    Ordinal(u16),
}

impl ImportSymbol {
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name { name, .. } => Some(name),
            Self::Ordinal(_) => None,
        }
    }

    pub const fn ordinal(&self) -> Option<u16> {
        match self {
            Self::Name { .. } => None,
            Self::Ordinal(value) => Some(*value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Import {
    library: Option<String>,
    symbol: ImportSymbol,
    slot: u64,
}

impl Import {
    pub(crate) fn new(library: Option<String>, symbol: ImportSymbol, slot: u64) -> Self {
        Self {
            library,
            symbol,
            slot,
        }
    }

    pub fn library(&self) -> Option<&str> {
        self.library.as_deref()
    }

    pub const fn symbol(&self) -> &ImportSymbol {
        &self.symbol
    }

    pub const fn slot(&self) -> u64 {
        self.slot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Export {
    name: String,
    ordinal: u32,
    address: u64,
    forwarder: bool,
}

impl Export {
    pub(crate) fn new(name: String, ordinal: u32, address: u64, forwarder: bool) -> Self {
        Self {
            name,
            ordinal,
            address,
            forwarder,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn address(&self) -> u64 {
        self.address
    }

    pub const fn is_forwarder(&self) -> bool {
        self.forwarder
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPlan {
    callbacks: Vec<u64>,
    template_file_offset: Option<u64>,
    template_file_size: u64,
    template_memory_size: u64,
    alignment: u64,
}

impl TlsPlan {
    pub(crate) fn new(
        callbacks: Vec<u64>,
        template_file_offset: Option<u64>,
        template_file_size: u64,
        template_memory_size: u64,
        alignment: u64,
    ) -> Result<Self, ParseError> {
        if callbacks.len() > crate::MAX_TLS_CALLBACKS {
            return Err(ParseError::LimitExceeded("TLS callback count"));
        }
        if template_file_size > template_memory_size {
            return Err(ParseError::Invalid(
                "TLS file template exceeds memory template",
            ));
        }
        if template_file_size != 0 && template_file_offset.is_none() {
            return Err(ParseError::Invalid("TLS file template has no file range"));
        }
        Ok(Self {
            callbacks,
            template_file_offset,
            template_file_size,
            template_memory_size,
            alignment,
        })
    }

    pub fn callbacks(&self) -> &[u64] {
        &self.callbacks
    }

    pub const fn template_file_offset(&self) -> Option<u64> {
        self.template_file_offset
    }

    pub const fn template_file_size(&self) -> u64 {
        self.template_file_size
    }

    pub const fn template_memory_size(&self) -> u64 {
        self.template_memory_size
    }

    pub const fn alignment(&self) -> u64 {
        self.alignment
    }

    pub fn is_present(&self) -> bool {
        self.template_memory_size != 0 || !self.callbacks.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitPlan {
    entry_point: Option<u64>,
    init_functions: Vec<u64>,
}

impl InitPlan {
    pub(crate) fn new(
        entry_point: Option<u64>,
        init_functions: Vec<u64>,
    ) -> Result<Self, ParseError> {
        if init_functions.len() > crate::MAX_INIT_FUNCTIONS {
            return Err(ParseError::LimitExceeded("initializer count"));
        }
        Ok(Self {
            entry_point,
            init_functions,
        })
    }

    pub const fn entry_point(&self) -> Option<u64> {
        self.entry_point
    }

    pub fn init_functions(&self) -> &[u64] {
        &self.init_functions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManualMapPlan {
    format: ImageFormat,
    image_base: u64,
    image_size: u64,
    alignment: u64,
    header: Option<MapRegion>,
    regions: Vec<MapRegion>,
    relocations: Vec<Relocation>,
    imports: Vec<Import>,
    exports: Vec<Export>,
    tls: TlsPlan,
    init: InitPlan,
    executable_ranges: Vec<AddressRange>,
}

impl ManualMapPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        format: ImageFormat,
        image_base: u64,
        image_size: u64,
        alignment: u64,
        header: Option<MapRegion>,
        regions: Vec<MapRegion>,
        relocations: Vec<Relocation>,
        imports: Vec<Import>,
        exports: Vec<Export>,
        tls: TlsPlan,
        init: InitPlan,
        executable_ranges: Vec<AddressRange>,
    ) -> Result<Self, ParseError> {
        if image_size == 0 || image_size > crate::MAX_IMAGE_SIZE {
            return Err(ParseError::LimitExceeded("mapped image size"));
        }
        if alignment == 0 || !crate::is_power_of_two(alignment) {
            return Err(ParseError::Invalid("mapping alignment"));
        }
        if regions.len() > crate::MAX_SEGMENTS.max(crate::MAX_SECTIONS) {
            return Err(ParseError::LimitExceeded("mapping region count"));
        }
        if relocations.len() > crate::MAX_RELOCATIONS {
            return Err(ParseError::LimitExceeded("relocation count"));
        }
        if imports.len() > crate::MAX_IMPORTS {
            return Err(ParseError::LimitExceeded("import count"));
        }
        if exports.len() > crate::MAX_EXPORTS {
            return Err(ParseError::LimitExceeded("export count"));
        }
        for region in &regions {
            if region.virtual_address + region.memory_size > image_size {
                return Err(ParseError::OutOfBounds("mapping region exceeds image"));
            }
            if region.protection.write && region.protection.execute {
                return Err(ParseError::WriteExecute);
            }
        }
        if let Some(header) = &header {
            if header.virtual_address + header.memory_size > image_size {
                return Err(ParseError::OutOfBounds("image headers exceed image"));
            }
        }
        for pair in executable_ranges.windows(2) {
            if pair[0].end() > pair[1].start() {
                return Err(ParseError::Invalid("overlapping executable ranges"));
            }
        }
        Ok(Self {
            format,
            image_base,
            image_size,
            alignment,
            header,
            regions,
            relocations,
            imports,
            exports,
            tls,
            init,
            executable_ranges,
        })
    }

    pub const fn format(&self) -> ImageFormat {
        self.format
    }

    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    pub const fn image_size(&self) -> u64 {
        self.image_size
    }

    pub const fn alignment(&self) -> u64 {
        self.alignment
    }

    pub const fn header(&self) -> Option<&MapRegion> {
        self.header.as_ref()
    }

    pub fn regions(&self) -> &[MapRegion] {
        &self.regions
    }

    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    pub const fn tls(&self) -> &TlsPlan {
        &self.tls
    }

    pub const fn init(&self) -> &InitPlan {
        &self.init
    }

    pub fn executable_ranges(&self) -> &[AddressRange] {
        &self.executable_ranges
    }

    pub fn export(&self, name: &str) -> Option<&Export> {
        self.exports.iter().find(|export| export.name == name)
    }

    pub fn require_r1_exports(&self) -> Result<(), crate::ShellError> {
        for name in R1_REQUIRED_EXPORTS {
            let export = self
                .export(name)
                .ok_or(crate::ShellError::MissingRequiredExport(name))?;
            if export.forwarder {
                return Err(crate::ShellError::ForwardedRequiredExport(name.to_owned()));
            }
            if !self
                .executable_ranges
                .iter()
                .any(|range| range.contains(export.address))
            {
                return Err(crate::ShellError::Parse(ParseError::OutOfBounds(
                    "required export is not executable",
                )));
            }
        }
        Ok(())
    }

    pub fn execute<B: MapBackend>(
        &self,
        image: &[u8],
        backend: &mut B,
    ) -> Result<B::Mapping, MapExecutionError<B::Error>> {
        let mapping = backend
            .allocate(self.image_size, self.alignment)
            .map_err(MapExecutionError::Backend)?;
        if let Err(error) = self.execute_into(image, backend, &mapping) {
            backend.release(mapping);
            return Err(error);
        }
        Ok(mapping)
    }

    fn execute_into<B: MapBackend>(
        &self,
        image: &[u8],
        backend: &mut B,
        mapping: &B::Mapping,
    ) -> Result<(), MapExecutionError<B::Error>> {
        if let Some(header) = &self.header {
            copy_region(image, header, backend, mapping)?;
        }
        for region in &self.regions {
            copy_region(image, region, backend, mapping)?;
        }
        for relocation in &self.relocations {
            backend
                .apply_relocation(mapping, relocation)
                .map_err(MapExecutionError::Backend)?;
        }
        for import in &self.imports {
            let address = backend
                .resolve_import(import)
                .map_err(MapExecutionError::Backend)?;
            backend
                .write_import(mapping, import.slot, address)
                .map_err(MapExecutionError::Backend)?;
        }
        for region in &self.regions {
            backend
                .protect(mapping, region)
                .map_err(MapExecutionError::Backend)?;
        }
        backend
            .initialize_tls(mapping, &self.tls)
            .map_err(MapExecutionError::Backend)?;
        backend
            .call_initializers(mapping, &self.init)
            .map_err(MapExecutionError::Backend)?;
        backend
            .publish_exports(mapping, &self.exports)
            .map_err(MapExecutionError::Backend)?;
        Ok(())
    }
}

fn copy_region<B: MapBackend>(
    image: &[u8],
    region: &MapRegion,
    backend: &mut B,
    mapping: &B::Mapping,
) -> Result<(), MapExecutionError<B::Error>> {
    let file_start = usize::try_from(region.file_offset)
        .map_err(|_| MapExecutionError::InvalidImage("file offset does not fit host"))?;
    let file_size = usize::try_from(region.file_size)
        .map_err(|_| MapExecutionError::InvalidImage("file size does not fit host"))?;
    let file_end = file_start
        .checked_add(file_size)
        .ok_or(MapExecutionError::InvalidImage("file range overflow"))?;
    if file_end > image.len() {
        return Err(MapExecutionError::InvalidImage("file range exceeds image"));
    }
    if file_size != 0 {
        backend
            .copy(
                mapping,
                region.virtual_address,
                &image[file_start..file_end],
            )
            .map_err(MapExecutionError::Backend)?;
    }
    if region.memory_size > region.file_size {
        backend
            .zero(
                mapping,
                region.virtual_address + region.file_size,
                region.memory_size - region.file_size,
            )
            .map_err(MapExecutionError::Backend)?;
    }
    Ok(())
}

pub trait MapBackend {
    type Mapping;
    type Error;

    fn allocate(&mut self, image_size: u64, alignment: u64) -> Result<Self::Mapping, Self::Error>;
    fn copy(
        &mut self,
        mapping: &Self::Mapping,
        virtual_address: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn zero(
        &mut self,
        mapping: &Self::Mapping,
        virtual_address: u64,
        length: u64,
    ) -> Result<(), Self::Error>;
    fn apply_relocation(
        &mut self,
        mapping: &Self::Mapping,
        relocation: &Relocation,
    ) -> Result<(), Self::Error>;
    fn resolve_import(&mut self, import: &Import) -> Result<u64, Self::Error>;
    fn write_import(
        &mut self,
        mapping: &Self::Mapping,
        virtual_address: u64,
        address: u64,
    ) -> Result<(), Self::Error>;
    fn protect(&mut self, mapping: &Self::Mapping, region: &MapRegion) -> Result<(), Self::Error>;
    fn initialize_tls(&mut self, mapping: &Self::Mapping, tls: &TlsPlan)
        -> Result<(), Self::Error>;
    fn call_initializers(
        &mut self,
        mapping: &Self::Mapping,
        init: &InitPlan,
    ) -> Result<(), Self::Error>;
    fn publish_exports(
        &mut self,
        mapping: &Self::Mapping,
        exports: &[Export],
    ) -> Result<(), Self::Error>;
    fn release(&mut self, mapping: Self::Mapping);
}

#[derive(Debug)]
pub enum MapExecutionError<E> {
    Backend(E),
    InvalidImage(&'static str),
}

impl<E: fmt::Display> fmt::Display for MapExecutionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => write!(formatter, "mapping backend failed: {error}"),
            Self::InvalidImage(reason) => write!(formatter, "mapping input is invalid: {reason}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for MapExecutionError<E> {}
