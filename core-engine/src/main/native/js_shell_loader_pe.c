#include "js_shell_loader.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *g_js_shell_loader_failure = "pe64 loader has not started";

typedef BOOL (WINAPI *js_shell_dll_main)(HINSTANCE instance, DWORD reason, LPVOID reserved);
typedef void (NTAPI *js_shell_tls_callback)(PVOID dll_handle, DWORD reason, PVOID reserved);

#define JS_SHELL_MAX_PE_SECTIONS 96u
#define JS_SHELL_MAX_PE_IMPORT_MODULE_CACHE 32u

typedef struct js_shell_pe_section_plan {
    DWORD raw_offset;
    DWORD copy_size;
    DWORD virtual_address;
    DWORD mapped_size;
    DWORD protection;
} js_shell_pe_section_plan;

/* Public, immutable geometry derived from the authenticated PE once for this
 * load.  The plan does not carry payload data, secrets, or import addresses;
 * every load still validates the source image, mapped ranges, relocations,
 * imports, exports, and executable entries before publishing it. */
typedef struct js_shell_pe_image_plan {
    IMAGE_NT_HEADERS64 nt;
    js_shell_pe_section_plan sections[JS_SHELL_MAX_PE_SECTIONS];
    WORD section_count;
    DWORD header_copy_size;
    DWORD executable_rva_low;
    DWORD executable_rva_high;
} js_shell_pe_image_plan;

typedef struct js_shell_pe_import_module_cache_entry {
    const char *name;
    HMODULE module;
} js_shell_pe_import_module_cache_entry;

static void js_shell_loader_fail(const char *reason) {
    g_js_shell_loader_failure = reason;
}

static void js_shell_loader_trace(const char *stage) {
    if (GetEnvironmentVariableA("JS_SHELL_DEBUG", 0, 0) > 0) {
        fprintf(stderr, "[js-shell-pe] %s\n", stage);
        fflush(stderr);
    }
}

static int js_shell_validate_range(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

static int js_shell_pointer_in_range(uintptr_t low, uintptr_t high, const void *ptr) {
    uintptr_t value = (uintptr_t)ptr;
    return low && high > low && value >= low && value < high;
}

static int js_shell_image_range_contains(const void *image, const IMAGE_NT_HEADERS64 *nt, const void *ptr, size_t size) {
    uintptr_t low = (uintptr_t)image;
    uintptr_t high = low + (uintptr_t)nt->OptionalHeader.SizeOfImage;
    uintptr_t value = (uintptr_t)ptr;
    return image && ptr && high >= low && value >= low && value <= high && size <= high - value;
}

static DWORD js_shell_section_protect(DWORD characteristics) {
    int executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    int readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    int writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (executable) {
        if (readable) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (writable) return PAGE_READWRITE;
    if (readable) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static void *js_shell_rva(void *image, DWORD rva) {
    return (void *)((uintptr_t)image + (uintptr_t)rva);
}

static WORD js_shell_read_word(const void *source) {
    WORD value;
    memcpy(&value, source, sizeof(value));
    return value;
}

static DWORD js_shell_read_dword(const void *source) {
    DWORD value;
    memcpy(&value, source, sizeof(value));
    return value;
}

static uintptr_t js_shell_read_uintptr(const void *source) {
    uintptr_t value;
    memcpy(&value, source, sizeof(value));
    return value;
}

static void js_shell_write_uintptr(void *destination, uintptr_t value) {
    memcpy(destination, &value, sizeof(value));
}

static int js_shell_rva_range_contains(const IMAGE_NT_HEADERS64 *nt, DWORD rva, size_t size) {
    return rva <= nt->OptionalHeader.SizeOfImage && size <= (size_t)nt->OptionalHeader.SizeOfImage - (size_t)rva;
}

static int js_shell_image_cstring_contains(const void *image, const IMAGE_NT_HEADERS64 *nt, const char *text) {
    if (!image || !nt || !text) return 0;
    uintptr_t low = (uintptr_t)image;
    uintptr_t high = low + (uintptr_t)nt->OptionalHeader.SizeOfImage;
    uintptr_t cursor = (uintptr_t)text;
    if (high < low || cursor < low || cursor >= high) return 0;
    while (cursor < high) {
        if (*(const char *)cursor == '\0') return 1;
        cursor++;
    }
    return 0;
}

static int js_shell_apply_relocations(void *image, const IMAGE_NT_HEADERS64 *nt, uintptr_t delta) {
    if (!delta) return 1;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) {
        js_shell_loader_fail("pe64 relocation delta exists but relocation table is missing");
        return 0;
    }
    if (!js_shell_rva_range_contains(nt, dir.VirtualAddress, dir.Size)) {
        js_shell_loader_fail("pe64 relocation directory is outside the mapped image");
        return 0;
    }
    /* The directory range is already authenticated and bounded in the mapped
     * image.  Walk a single validated cursor through relocation blocks rather
     * than re-deriving the RVA address for every block; target-slot bounds
     * remain checked for every relocation entry. */
    const unsigned char *cursor = (const unsigned char *)js_shell_rva(image, dir.VirtualAddress);
    const unsigned char *directory_end = cursor + (size_t)dir.Size;
    while (cursor < directory_end) {
        size_t remaining = (size_t)(directory_end - cursor);
        if (remaining < sizeof(IMAGE_BASE_RELOCATION)) {
            js_shell_loader_fail("pe64 relocation block header is truncated");
            return 0;
        }
        IMAGE_BASE_RELOCATION block;
        memcpy(&block, cursor, sizeof(block));
        if (!block.SizeOfBlock || block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block.SizeOfBlock > remaining) {
            js_shell_loader_fail("pe64 relocation block is outside the relocation directory");
            return 0;
        }
        DWORD entry_count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const unsigned char *entries = cursor + sizeof(IMAGE_BASE_RELOCATION);
        for (DWORD i = 0; i < entry_count; i++) {
            WORD entry = js_shell_read_word(entries + (size_t)i * sizeof(WORD));
            WORD type = entry >> 12;
            WORD reloc_offset = entry & 0x0fffu;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_DIR64) {
                js_shell_loader_fail("pe64 relocation type is not supported by the max shell loader");
                return 0;
            }
            if (block.VirtualAddress > UINT32_MAX - reloc_offset) {
                js_shell_loader_fail("pe64 relocation target slot is outside the mapped image");
                return 0;
            }
            DWORD target_rva = block.VirtualAddress + reloc_offset;
            void *slot = js_shell_rva(image, target_rva);
            if (!js_shell_rva_range_contains(nt, target_rva, sizeof(uintptr_t))) {
                js_shell_loader_fail("pe64 relocation target slot is outside the mapped image");
                return 0;
            }
            js_shell_write_uintptr(slot, js_shell_read_uintptr(slot) + delta);
        }
        cursor += block.SizeOfBlock;
    }
    return 1;
}

static FARPROC js_shell_import_symbol(void *image, const IMAGE_NT_HEADERS64 *nt, HMODULE module, const IMAGE_THUNK_DATA64 *name_thunk) {
    if (name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
        return GetProcAddress(module, (LPCSTR)(uintptr_t)IMAGE_ORDINAL64(name_thunk->u1.Ordinal));
    }
    if (!js_shell_rva_range_contains(nt, (DWORD)name_thunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME))) {
        js_shell_loader_fail("pe64 import-by-name header is outside the mapped image");
        return 0;
    }
    const char *import_name = (const char *)js_shell_rva(
        image,
        (DWORD)name_thunk->u1.AddressOfData + (DWORD)offsetof(IMAGE_IMPORT_BY_NAME, Name));
    if (!js_shell_image_cstring_contains(image, nt, import_name)) {
        js_shell_loader_fail("pe64 import symbol name is outside the mapped image");
        return 0;
    }
    return GetProcAddress(module, import_name);
}

static HMODULE js_shell_import_module_cached(
    const char *dll_name,
    js_shell_pe_import_module_cache_entry *cache,
    size_t *cache_count
) {
    if (!dll_name || !cache || !cache_count) return 0;
    for (size_t i = 0u; i < *cache_count; i++) {
        if (cache[i].module && cache[i].name && strcmp(cache[i].name, dll_name) == 0) {
            return cache[i].module;
        }
    }
    HMODULE module = LoadLibraryA(dll_name);
    if (!module) return 0;
    if (*cache_count < JS_SHELL_MAX_PE_IMPORT_MODULE_CACHE) {
        cache[*cache_count].name = dll_name;
        cache[*cache_count].module = module;
        (*cache_count)++;
    }
    return module;
}

static int js_shell_resolve_imports(void *image, const IMAGE_NT_HEADERS64 *nt) {
    js_shell_pe_import_module_cache_entry module_cache[JS_SHELL_MAX_PE_IMPORT_MODULE_CACHE];
    size_t module_cache_count = 0u;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    memset(module_cache, 0, sizeof(module_cache));
    if (!dir.VirtualAddress || !dir.Size) return 1;
    if (!js_shell_rva_range_contains(nt, dir.VirtualAddress, dir.Size)) {
        js_shell_loader_fail("pe64 import directory is outside the mapped image");
        return 0;
    }
    const unsigned char *descriptors = (const unsigned char *)js_shell_rva(image, dir.VirtualAddress);
    DWORD descriptor_count = dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (DWORD desc_index = 0; desc_index < descriptor_count; desc_index++) {
        const unsigned char *desc_bytes = descriptors + (size_t)desc_index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!js_shell_image_range_contains(image, nt, desc_bytes, sizeof(desc))) {
            js_shell_loader_fail("pe64 import descriptor is outside the mapped image");
            return 0;
        }
        memcpy(&desc, desc_bytes, sizeof(desc));
        if (!desc.OriginalFirstThunk && !desc.FirstThunk && !desc.Name) return 1;
        if (!desc.Name) {
            js_shell_loader_fail("pe64 import descriptor is missing a DLL name");
            return 0;
        }
        if (!js_shell_rva_range_contains(nt, desc.Name, 1)) {
            js_shell_loader_fail("pe64 import DLL name is outside the mapped image");
            return 0;
        }
        const char *dll_name = (const char *)js_shell_rva(image, desc.Name);
        if (!js_shell_image_cstring_contains(image, nt, dll_name)) {
            js_shell_loader_fail("pe64 import DLL name is outside the mapped image");
            return 0;
        }
        HMODULE module = js_shell_import_module_cached(dll_name, module_cache, &module_cache_count);
        if (!module) {
            js_shell_loader_fail("pe64 import DLL could not be loaded");
            return 0;
        }
        DWORD name_thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        DWORD iat_rva = desc.FirstThunk;
        for (DWORD thunk_index = 0;; thunk_index++) {
            size_t thunk_offset = (size_t)thunk_index * sizeof(IMAGE_THUNK_DATA64);
            if (thunk_offset > UINT32_MAX || name_thunk_rva > UINT32_MAX - (DWORD)thunk_offset || iat_rva > UINT32_MAX - (DWORD)thunk_offset ||
                !js_shell_rva_range_contains(nt, name_thunk_rva + (DWORD)thunk_offset, sizeof(IMAGE_THUNK_DATA64)) ||
                !js_shell_rva_range_contains(nt, iat_rva + (DWORD)thunk_offset, sizeof(IMAGE_THUNK_DATA64))) {
                js_shell_loader_fail("pe64 import thunk slot is outside the mapped image");
                return 0;
            }
            const void *name_thunk_bytes = js_shell_rva(image, name_thunk_rva + (DWORD)thunk_offset);
            void *iat_bytes = js_shell_rva(image, iat_rva + (DWORD)thunk_offset);
            IMAGE_THUNK_DATA64 name_thunk;
            memcpy(&name_thunk, name_thunk_bytes, sizeof(name_thunk));
            if (!name_thunk.u1.AddressOfData) break;
            FARPROC symbol = js_shell_import_symbol(image, nt, module, &name_thunk);
            if (!symbol) {
                js_shell_loader_fail("pe64 import symbol could not be resolved");
                return 0;
            }
            ULONGLONG function = (ULONGLONG)(uintptr_t)symbol;
            memcpy(iat_bytes, &function, sizeof(function));
        }
    }
    js_shell_loader_fail("pe64 import descriptor table is missing a terminator");
    return 0;
}

static void js_shell_run_tls_callbacks(void *image, js_shell_tls_callback *callbacks, size_t callback_count, DWORD reason) {
    for (size_t i = 0u; callbacks && i < callback_count; i++) {
        js_shell_tls_callback callback;
        memcpy(&callback, callbacks + i, sizeof(callback));
        callback(image, reason, 0);
    }
}

static int js_shell_build_image_plan(
    const unsigned char *bytes,
    size_t size,
    const IMAGE_DOS_HEADER *dos,
    js_shell_pe_image_plan *out_plan
) {
    IMAGE_NT_HEADERS64 nt;
    DWORD executable_low = UINT32_MAX;
    DWORD executable_high = 0u;

    if (!bytes || !dos || !out_plan || dos->e_lfanew <= 0 ||
        !js_shell_validate_range((size_t)dos->e_lfanew, sizeof(nt), size)) {
        js_shell_loader_fail("pe64 DOS/NT headers are invalid");
        return 0;
    }
    memset(out_plan, 0, sizeof(*out_plan));
    memcpy(&nt, bytes + dos->e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        js_shell_loader_fail("pe64 payload is not a supported AMD64 PE image");
        return 0;
    }
    if (nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > JS_SHELL_MAX_PE_SECTIONS) {
        js_shell_loader_fail("pe64 optional header or section count is invalid");
        return 0;
    }
    if (!(nt.FileHeader.Characteristics & IMAGE_FILE_DLL) || nt.OptionalHeader.SizeOfImage == 0u) {
        js_shell_loader_fail("pe64 payload is not a DLL image");
        return 0;
    }
    if (nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS) {
        js_shell_loader_fail("pe64 optional header does not declare required data directories");
        return 0;
    }
    if (nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage) {
        js_shell_loader_fail("pe64 header range is outside the mapped image");
        return 0;
    }
    if (!js_shell_validate_range(
            (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64),
            (size_t)nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
            size)) {
        js_shell_loader_fail("pe64 section table is out of range");
        return 0;
    }

    out_plan->nt = nt;
    out_plan->section_count = nt.FileHeader.NumberOfSections;
    out_plan->header_copy_size = nt.OptionalHeader.SizeOfHeaders;
    if ((size_t)out_plan->header_copy_size > size) out_plan->header_copy_size = (DWORD)size;
    for (WORD i = 0; i < out_plan->section_count; i++) {
        IMAGE_SECTION_HEADER source;
        js_shell_pe_section_plan *entry = &out_plan->sections[i];
        DWORD mapped_size;

        memcpy(
            &source,
            bytes + (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (size_t)i * sizeof(source),
            sizeof(source));
        if ((source.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) ==
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) {
            js_shell_loader_fail("pe64 section requests writable executable memory");
            return 0;
        }
        mapped_size = source.Misc.VirtualSize ? source.Misc.VirtualSize : source.SizeOfRawData;
        if (mapped_size != 0u &&
            (source.VirtualAddress > nt.OptionalHeader.SizeOfImage ||
             mapped_size > nt.OptionalHeader.SizeOfImage - source.VirtualAddress)) {
            js_shell_loader_fail("pe64 section virtual range is out of image bounds");
            return 0;
        }
        if (source.SizeOfRawData != 0u &&
            !js_shell_validate_range(source.PointerToRawData, source.SizeOfRawData, size)) {
            js_shell_loader_fail("pe64 section raw data is out of range");
            return 0;
        }

        entry->raw_offset = source.PointerToRawData;
        entry->copy_size = source.SizeOfRawData < mapped_size ? source.SizeOfRawData : mapped_size;
        entry->virtual_address = source.VirtualAddress;
        entry->mapped_size = mapped_size;
        entry->protection = js_shell_section_protect(source.Characteristics);
        if ((source.Characteristics & IMAGE_SCN_MEM_EXECUTE) && mapped_size != 0u) {
            DWORD section_end = source.VirtualAddress + mapped_size;
            if (source.VirtualAddress < executable_low) executable_low = source.VirtualAddress;
            if (section_end > executable_high) executable_high = section_end;
        }
    }
    if (executable_low == UINT32_MAX || executable_high <= executable_low) {
        js_shell_loader_fail("pe64 payload has no executable section");
        return 0;
    }
    out_plan->executable_rva_low = executable_low;
    out_plan->executable_rva_high = executable_high;
    return 1;
}

static int js_shell_plan_executable_bounds(
    void *image,
    const js_shell_pe_image_plan *plan,
    uintptr_t *out_low,
    uintptr_t *out_high
) {
    uintptr_t low;
    uintptr_t high;
    if (!image || !plan || plan->executable_rva_high <= plan->executable_rva_low ||
        plan->executable_rva_high > plan->nt.OptionalHeader.SizeOfImage ||
        (uintptr_t)plan->nt.OptionalHeader.SizeOfImage > UINTPTR_MAX - (uintptr_t)image) {
        js_shell_loader_fail("pe64 executable section range is out of image bounds");
        return 0;
    }
    low = (uintptr_t)image + (uintptr_t)plan->executable_rva_low;
    high = (uintptr_t)image + (uintptr_t)plan->executable_rva_high;
    if (high <= low) {
        js_shell_loader_fail("pe64 executable section range overflows");
        return 0;
    }
    if (out_low) *out_low = low;
    if (out_high) *out_high = high;
    return 1;
}

static int js_shell_validate_tls_callbacks(
    void *image,
    const IMAGE_NT_HEADERS64 *nt,
    uintptr_t exec_low,
    uintptr_t exec_high,
    js_shell_tls_callback **out_callbacks,
    size_t *out_callback_count
) {
    if (out_callbacks) *out_callbacks = 0;
    if (out_callback_count) *out_callback_count = 0u;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) return 1;
    const void *tls_bytes = js_shell_rva(image, dir.VirtualAddress);
    IMAGE_TLS_DIRECTORY64 tls;
    if (!js_shell_image_range_contains(image, nt, tls_bytes, sizeof(tls))) {
        js_shell_loader_fail("pe64 TLS directory is outside the mapped image");
        return 0;
    }
    memcpy(&tls, tls_bytes, sizeof(tls));
    if (!tls.AddressOfCallBacks) return 1;
    js_shell_tls_callback *callbacks = (js_shell_tls_callback *)(uintptr_t)tls.AddressOfCallBacks;
    for (size_t callback_count = 0u;; callback_count++) {
        if (!js_shell_image_range_contains(image, nt, callbacks, sizeof(*callbacks))) {
            js_shell_loader_fail("pe64 TLS callback table is outside the mapped image");
            return 0;
        }
        js_shell_tls_callback callback;
        memcpy(&callback, callbacks, sizeof(callback));
        if (!callback) break;
        if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)callback)) {
            js_shell_loader_fail("pe64 TLS callback is outside executable image pages");
            return 0;
        }
        callbacks++;
        if (out_callback_count) *out_callback_count = callback_count + 1u;
    }
    if (out_callbacks) *out_callbacks = (js_shell_tls_callback *)(uintptr_t)tls.AddressOfCallBacks;
    return 1;
}

static PRUNTIME_FUNCTION js_shell_register_exception_table(void *image, const IMAGE_NT_HEADERS64 *nt, DWORD *out_count) {
    (void)image;
    (void)nt;
    if (out_count) *out_count = 0;
    /* The inner kernel does not throw C++/SEH exceptions across the manual-map
     * boundary. Leaving unwind tables unregistered avoids process-exit fast-fail
     * paths that assume OS-loader-owned module lifetimes. */
    return 0;
#if 0
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    DWORD count = dir.Size / sizeof(RUNTIME_FUNCTION);
    if (!count) return 0;
    PRUNTIME_FUNCTION table = (PRUNTIME_FUNCTION)js_shell_rva(image, dir.VirtualAddress);
    if (!RtlAddFunctionTable(table, count, (DWORD64)(uintptr_t)image)) {
        js_shell_loader_fail("pe64 exception table registration failed");
        return (PRUNTIME_FUNCTION)(uintptr_t)1u;
    }
    if (out_count) *out_count = count;
    return table;
#endif
}

typedef struct js_shell_pe_export_index {
    const unsigned char *names;
    const unsigned char *ordinals;
    const unsigned char *functions;
    DWORD name_count;
    DWORD function_count;
} js_shell_pe_export_index;

static int js_shell_prepare_export_index(
    void *image,
    const IMAGE_NT_HEADERS64 *nt,
    js_shell_pe_export_index *out_index
) {
    IMAGE_DATA_DIRECTORY dir;
    IMAGE_EXPORT_DIRECTORY exports;
    const void *export_bytes;
    if (!image || !nt || !out_index) return 0;
    memset(out_index, 0, sizeof(*out_index));
    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 1;
    if (!js_shell_rva_range_contains(nt, dir.VirtualAddress, dir.Size)) {
        js_shell_loader_fail("pe64 export directory is outside the mapped image");
        return 0;
    }
    export_bytes = js_shell_rva(image, dir.VirtualAddress);
    if (!js_shell_image_range_contains(image, nt, export_bytes, sizeof(exports))) {
        js_shell_loader_fail("pe64 export directory header is outside the mapped image");
        return 0;
    }
    memcpy(&exports, export_bytes, sizeof(exports));
    if (!js_shell_rva_range_contains(nt, exports.AddressOfNames, (size_t)exports.NumberOfNames * sizeof(DWORD)) ||
        !js_shell_rva_range_contains(nt, exports.AddressOfNameOrdinals, (size_t)exports.NumberOfNames * sizeof(WORD)) ||
        !js_shell_rva_range_contains(nt, exports.AddressOfFunctions, (size_t)exports.NumberOfFunctions * sizeof(DWORD))) {
        js_shell_loader_fail("pe64 export name or function table is outside the mapped image");
        return 0;
    }
    out_index->names = (const unsigned char *)js_shell_rva(image, exports.AddressOfNames);
    out_index->ordinals = (const unsigned char *)js_shell_rva(image, exports.AddressOfNameOrdinals);
    out_index->functions = (const unsigned char *)js_shell_rva(image, exports.AddressOfFunctions);
    out_index->name_count = exports.NumberOfNames;
    out_index->function_count = exports.NumberOfFunctions;
    return 1;
}

static int js_shell_export_pointer_from_index(
    void *image,
    const IMAGE_NT_HEADERS64 *nt,
    const js_shell_pe_export_index *index,
    DWORD name_index,
    void **out_pointer
) {
    WORD ordinal;
    DWORD function_rva;
    if (!image || !nt || !index || !out_pointer || name_index >= index->name_count) return 0;
    ordinal = js_shell_read_word(index->ordinals + (size_t)name_index * sizeof(WORD));
    if (ordinal >= index->function_count) return 0;
    function_rva = js_shell_read_dword(index->functions + (size_t)ordinal * sizeof(DWORD));
    if (!js_shell_rva_range_contains(nt, function_rva, 1u)) {
        js_shell_loader_fail("pe64 export symbol address is outside the mapped image");
        return 0;
    }
    *out_pointer = js_shell_rva(image, function_rva);
    return 1;
}

/* Build a one-load export lookup index and scan it once for the two required
 * entrypoints.  Table, name-string, ordinal, and function-RVA checks remain
 * mandatory on every load; the optimization only removes the second identical
 * traversal of validated export metadata. */
static int js_shell_resolve_required_exports(
    void *image,
    const IMAGE_NT_HEADERS64 *nt,
    void **out_jni_on_load,
    void **out_native_abi_table
) {
    js_shell_pe_export_index index;
    void *jni_on_load = 0;
    void *native_abi_table = 0;
    if (!out_jni_on_load || !out_native_abi_table ||
        !js_shell_prepare_export_index(image, nt, &index)) {
        return 0;
    }
    for (DWORD i = 0u; i < index.name_count; i++) {
        DWORD name_rva = js_shell_read_dword(index.names + (size_t)i * sizeof(DWORD));
        const char *export_name;
        if (!js_shell_rva_range_contains(nt, name_rva, 1u)) {
            js_shell_loader_fail("pe64 export name is outside the mapped image");
            return 0;
        }
        export_name = (const char *)js_shell_rva(image, name_rva);
        if (!js_shell_image_cstring_contains(image, nt, export_name)) {
            js_shell_loader_fail("pe64 export name is outside the mapped image");
            return 0;
        }
        if (!jni_on_load && strcmp(export_name, "JNI_OnLoad") == 0) {
            if (!js_shell_export_pointer_from_index(image, nt, &index, i, &jni_on_load)) return 0;
        } else if (!native_abi_table && strcmp(export_name, "js_native_abi_table_v1") == 0) {
            if (!js_shell_export_pointer_from_index(image, nt, &index, i, &native_abi_table)) return 0;
        }
        if (jni_on_load && native_abi_table) break;
    }
    if (!jni_on_load) {
        js_shell_loader_fail("pe64 payload does not export JNI_OnLoad");
        return 0;
    }
    if (!native_abi_table) {
        js_shell_loader_fail("pe64 payload does not export native ABI table");
        return 0;
    }
    *out_jni_on_load = jni_on_load;
    *out_native_abi_table = native_abi_table;
    return 1;
}

int js_shell_load_inner_image(const js_shell_payload_view *payload, js_shell_loaded_image *out_image) {
    if (!payload || !out_image || !payload->decoded_payload || payload->decoded_payload_size < sizeof(IMAGE_DOS_HEADER)) {
        js_shell_loader_fail("pe64 payload is empty or missing decoded bytes");
        return 0;
    }
    memset(out_image, 0, sizeof(*out_image));
    js_shell_loader_trace("start");
    const unsigned char *bytes = payload->decoded_payload;
    size_t size = payload->decoded_payload_size;
    IMAGE_DOS_HEADER dos;
    js_shell_pe_image_plan plan;
    memcpy(&dos, bytes, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        js_shell_loader_fail("pe64 DOS/NT headers are invalid");
        return 0;
    }
    if (!js_shell_build_image_plan(bytes, size, &dos, &plan)) return 0;
    const IMAGE_NT_HEADERS64 *nt = &plan.nt;

    void *image = VirtualAlloc(0, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image) {
        js_shell_loader_fail("pe64 VirtualAlloc failed");
        return 0;
    }
    memcpy(image, bytes, (size_t)plan.header_copy_size);
    js_shell_loader_trace("mapped headers");
    for (WORD i = 0; i < plan.section_count; i++) {
        const js_shell_pe_section_plan *section = &plan.sections[i];
        if (section->copy_size == 0u) continue;
        memcpy((unsigned char *)image + section->virtual_address, bytes + section->raw_offset, section->copy_size);
    }

    uintptr_t delta = (uintptr_t)image - (uintptr_t)nt->OptionalHeader.ImageBase;
    if (!js_shell_apply_relocations(image, nt, delta) || !js_shell_resolve_imports(image, nt)) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    js_shell_loader_trace("relocated imports");

    for (WORD i = 0; i < plan.section_count; i++) {
        const js_shell_pe_section_plan *section = &plan.sections[i];
        DWORD old_protect = 0;
        if (section->mapped_size == 0u) continue;
        if (!VirtualProtect((unsigned char *)image + section->virtual_address, section->mapped_size, section->protection, &old_protect)) {
            VirtualFree(image, 0, MEM_RELEASE);
            js_shell_loader_fail("pe64 section VirtualProtect failed");
            return 0;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage);
    js_shell_loader_trace("protected sections");
    uintptr_t exec_low = 0;
    uintptr_t exec_high = 0;
    if (!js_shell_plan_executable_bounds(image, &plan, &exec_low, &exec_high)) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    DWORD function_count = 0;
    PRUNTIME_FUNCTION function_table = js_shell_register_exception_table(image, nt, &function_count);
    if (function_table == (PRUNTIME_FUNCTION)(uintptr_t)1u) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    js_shell_loader_trace("registered exception table");
    js_shell_tls_callback *tls_callbacks = 0;
    size_t tls_callback_count = 0u;
    if (!js_shell_validate_tls_callbacks(image, nt, exec_low, exec_high, &tls_callbacks, &tls_callback_count)) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    js_shell_run_tls_callbacks(image, tls_callbacks, tls_callback_count, DLL_PROCESS_ATTACH);
    js_shell_loader_trace("ran tls callbacks for manual image");
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        js_shell_dll_main entry = (js_shell_dll_main)js_shell_rva(image, nt->OptionalHeader.AddressOfEntryPoint);
        if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)entry)) {
            VirtualFree(image, 0, MEM_RELEASE);
            js_shell_loader_fail("pe64 DllMain entrypoint is outside executable image pages");
            return 0;
        }
        if (!entry((HINSTANCE)image, DLL_PROCESS_ATTACH, 0)) {
            VirtualFree(image, 0, MEM_RELEASE);
            js_shell_loader_fail("pe64 DllMain process attach failed");
            return 0;
        }
    }
    /* Keep detach/free disabled: the OS loader does not own this module, and
     * native method trampolines may still point into process-lifetime state. */
    js_shell_loader_trace("ran dllmain attach for manual image");

    void *resolved_jni_on_load = 0;
    void *resolved_native_abi_table = 0;
    if (!js_shell_resolve_required_exports(image, nt, &resolved_jni_on_load, &resolved_native_abi_table)) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    out_image->jni_on_load = (jint (*)(JavaVM *, void *))resolved_jni_on_load;
    out_image->native_abi_table_v1 = (const js_native_abi_table *(*)(void))resolved_native_abi_table;
    /* The manually mapped inner PE is not registered with the OS loader. Keep
     * unload detached from JVM shutdown so native method/code pages and CRT
     * teardown state remain process-lifetime. */
    out_image->jni_on_unload = 0;
    if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)out_image->jni_on_load) ||
        !js_shell_pointer_in_range(exec_low, exec_high, (const void *)out_image->native_abi_table_v1)) {
        VirtualFree(image, 0, MEM_RELEASE);
        js_shell_loader_fail("pe64 exported JNI or ABI entry is outside executable image pages");
        return 0;
    }
    out_image->image_base = image;
    out_image->image_size = nt->OptionalHeader.SizeOfImage;
    out_image->code_low = (void *)exec_low;
    out_image->code_size = (size_t)(exec_high - exec_low);
    out_image->mapping_metadata.image_low = (uintptr_t)image;
    out_image->mapping_metadata.image_high = (uintptr_t)image + (uintptr_t)nt->OptionalHeader.SizeOfImage;
    out_image->mapping_metadata.code_low = exec_low;
    out_image->mapping_metadata.code_high = exec_high;
    out_image->mapping_metadata.mapping_unit_count = (unsigned int)plan.section_count;
    out_image->mapping_metadata.version = JS_SHELL_MAPPING_METADATA_VERSION;
    out_image->platform_data = 0;
    js_shell_loader_trace("resolved JNI_OnLoad");
    g_js_shell_loader_failure = "pe64 memory loader completed";
    return 1;
}

void js_shell_unload_inner_image(js_shell_loaded_image *image) {
    if (!image || !image->image_base) return;
    /* Keep the PE image process-lifetime. The image was manual-mapped, so the
     * OS loader never owns its TLS/DllMain lifecycle; running detach here can
     * re-enter CRT/JVM shutdown through unregistered module state. */
    memset(image, 0, sizeof(*image));
}

const char *js_shell_loader_failure_reason(void) { return g_js_shell_loader_failure; }

#endif
