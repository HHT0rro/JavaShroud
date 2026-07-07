#include "js_shell_loader.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *g_js_shell_loader_failure = "pe64 loader has not started";

typedef BOOL (WINAPI *js_shell_dll_main)(HINSTANCE instance, DWORD reason, LPVOID reserved);
typedef void (NTAPI *js_shell_tls_callback)(PVOID dll_handle, DWORD reason, PVOID reserved);

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
        if (writable) return PAGE_EXECUTE_READWRITE;
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
    DWORD offset = 0;
    while (offset < dir.Size) {
        if (dir.Size - offset < sizeof(IMAGE_BASE_RELOCATION)) {
            js_shell_loader_fail("pe64 relocation block header is truncated");
            return 0;
        }
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)js_shell_rva(image, dir.VirtualAddress + offset);
        if (!block->SizeOfBlock || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block->SizeOfBlock > dir.Size - offset) {
            js_shell_loader_fail("pe64 relocation block is outside the relocation directory");
            return 0;
        }
        if (!js_shell_image_range_contains(image, nt, block, block->SizeOfBlock)) {
            js_shell_loader_fail("pe64 relocation block is outside the mapped image");
            return 0;
        }
        DWORD entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries = (WORD *)(block + 1);
        for (DWORD i = 0; i < entry_count; i++) {
            WORD type = entries[i] >> 12;
            WORD reloc_offset = entries[i] & 0x0fffu;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_DIR64) {
                js_shell_loader_fail("pe64 relocation type is not supported by the max shell loader");
                return 0;
            }
            if (block->VirtualAddress > UINT32_MAX - reloc_offset) {
                js_shell_loader_fail("pe64 relocation target slot is outside the mapped image");
                return 0;
            }
            DWORD target_rva = block->VirtualAddress + reloc_offset;
            uintptr_t *slot = (uintptr_t *)js_shell_rva(image, target_rva);
            if (!js_shell_rva_range_contains(nt, target_rva, sizeof(*slot))) {
                js_shell_loader_fail("pe64 relocation target slot is outside the mapped image");
                return 0;
            }
            *slot += delta;
        }
        offset += block->SizeOfBlock;
    }
    return 1;
}

static FARPROC js_shell_import_symbol(void *image, const IMAGE_NT_HEADERS64 *nt, HMODULE module, IMAGE_THUNK_DATA64 *name_thunk) {
    if (name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
        return GetProcAddress(module, (LPCSTR)(uintptr_t)IMAGE_ORDINAL64(name_thunk->u1.Ordinal));
    }
    if (!js_shell_rva_range_contains(nt, (DWORD)name_thunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME))) {
        js_shell_loader_fail("pe64 import-by-name header is outside the mapped image");
        return 0;
    }
    IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME *)js_shell_rva(image, (DWORD)name_thunk->u1.AddressOfData);
    if (!js_shell_image_cstring_contains(image, nt, (const char *)by_name->Name)) {
        js_shell_loader_fail("pe64 import symbol name is outside the mapped image");
        return 0;
    }
    return GetProcAddress(module, (LPCSTR)by_name->Name);
}

static int js_shell_resolve_imports(void *image, const IMAGE_NT_HEADERS64 *nt) {
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return 1;
    if (!js_shell_rva_range_contains(nt, dir.VirtualAddress, dir.Size)) {
        js_shell_loader_fail("pe64 import directory is outside the mapped image");
        return 0;
    }
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)js_shell_rva(image, dir.VirtualAddress);
    DWORD descriptor_count = dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (DWORD desc_index = 0; desc_index < descriptor_count; desc_index++, desc++) {
        if (!js_shell_image_range_contains(image, nt, desc, sizeof(*desc))) {
            js_shell_loader_fail("pe64 import descriptor is outside the mapped image");
            return 0;
        }
        if (!desc->OriginalFirstThunk && !desc->FirstThunk && !desc->Name) return 1;
        if (!desc->Name) {
            js_shell_loader_fail("pe64 import descriptor is missing a DLL name");
            return 0;
        }
        if (!js_shell_rva_range_contains(nt, desc->Name, 1)) {
            js_shell_loader_fail("pe64 import DLL name is outside the mapped image");
            return 0;
        }
        const char *dll_name = (const char *)js_shell_rva(image, desc->Name);
        if (!js_shell_image_cstring_contains(image, nt, dll_name)) {
            js_shell_loader_fail("pe64 import DLL name is outside the mapped image");
            return 0;
        }
        HMODULE module = LoadLibraryA(dll_name);
        if (!module) {
            js_shell_loader_fail("pe64 import DLL could not be loaded");
            return 0;
        }
        IMAGE_THUNK_DATA64 *name_thunk = (IMAGE_THUNK_DATA64 *)js_shell_rva(image, desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk);
        IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)js_shell_rva(image, desc->FirstThunk);
        DWORD name_thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        DWORD iat_rva = desc->FirstThunk;
        for (DWORD thunk_index = 0;; thunk_index++, name_thunk++, iat++) {
            size_t thunk_offset = (size_t)thunk_index * sizeof(IMAGE_THUNK_DATA64);
            if (thunk_offset > UINT32_MAX || name_thunk_rva > UINT32_MAX - (DWORD)thunk_offset || iat_rva > UINT32_MAX - (DWORD)thunk_offset ||
                !js_shell_rva_range_contains(nt, name_thunk_rva + (DWORD)thunk_offset, sizeof(*name_thunk)) || !js_shell_rva_range_contains(nt, iat_rva + (DWORD)thunk_offset, sizeof(*iat))) {
                js_shell_loader_fail("pe64 import thunk slot is outside the mapped image");
                return 0;
            }
            if (!name_thunk->u1.AddressOfData) break;
            FARPROC symbol = js_shell_import_symbol(image, nt, module, name_thunk);
            if (!symbol) {
                js_shell_loader_fail("pe64 import symbol could not be resolved");
                return 0;
            }
            iat->u1.Function = (ULONGLONG)(uintptr_t)symbol;
        }
    }
    js_shell_loader_fail("pe64 import descriptor table is missing a terminator");
    return 0;
}

static void js_shell_run_tls_callbacks(void *image, js_shell_tls_callback *callbacks, DWORD reason) {
    for (; callbacks && *callbacks; callbacks++) {
        (*callbacks)(image, reason, 0);
    }
}

static int js_shell_plan_executable_bounds(void *image, const IMAGE_NT_HEADERS64 *nt, uintptr_t *out_low, uintptr_t *out_high) {
    uintptr_t low = 0;
    uintptr_t high = 0;
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD virtual_size = section[i].Misc.VirtualSize ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
        if (!virtual_size) continue;
        if (section[i].VirtualAddress > nt->OptionalHeader.SizeOfImage || virtual_size > nt->OptionalHeader.SizeOfImage - section[i].VirtualAddress) {
            js_shell_loader_fail("pe64 executable section range is out of image bounds");
            return 0;
        }
        uintptr_t start = (uintptr_t)image + (uintptr_t)section[i].VirtualAddress;
        uintptr_t end = start + (uintptr_t)virtual_size;
        if (end < start) {
            js_shell_loader_fail("pe64 executable section range overflows");
            return 0;
        }
        if (!low || start < low) low = start;
        if (end > high) high = end;
    }
    if (!low || high <= low) {
        js_shell_loader_fail("pe64 payload has no executable section");
        return 0;
    }
    if (out_low) *out_low = low;
    if (out_high) *out_high = high;
    return 1;
}

static int js_shell_validate_tls_callbacks(void *image, const IMAGE_NT_HEADERS64 *nt, uintptr_t exec_low, uintptr_t exec_high, js_shell_tls_callback **out_callbacks) {
    if (out_callbacks) *out_callbacks = 0;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) return 1;
    IMAGE_TLS_DIRECTORY64 *tls = (IMAGE_TLS_DIRECTORY64 *)js_shell_rva(image, dir.VirtualAddress);
    if (!js_shell_image_range_contains(image, nt, tls, sizeof(*tls))) {
        js_shell_loader_fail("pe64 TLS directory is outside the mapped image");
        return 0;
    }
    if (!tls->AddressOfCallBacks) return 1;
    js_shell_tls_callback *callbacks = (js_shell_tls_callback *)(uintptr_t)tls->AddressOfCallBacks;
    for (;;) {
        if (!js_shell_image_range_contains(image, nt, callbacks, sizeof(*callbacks))) {
            js_shell_loader_fail("pe64 TLS callback table is outside the mapped image");
            return 0;
        }
        js_shell_tls_callback callback = *callbacks;
        if (!callback) break;
        if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)callback)) {
            js_shell_loader_fail("pe64 TLS callback is outside executable image pages");
            return 0;
        }
        callbacks++;
    }
    if (out_callbacks) *out_callbacks = (js_shell_tls_callback *)(uintptr_t)tls->AddressOfCallBacks;
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

static void *js_shell_find_export(void *image, const IMAGE_NT_HEADERS64 *nt, const char *name) {
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    if (!js_shell_rva_range_contains(nt, dir.VirtualAddress, dir.Size)) {
        js_shell_loader_fail("pe64 export directory is outside the mapped image");
        return 0;
    }
    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)js_shell_rva(image, dir.VirtualAddress);
    if (!js_shell_image_range_contains(image, nt, exports, sizeof(*exports))) {
        js_shell_loader_fail("pe64 export directory header is outside the mapped image");
        return 0;
    }
    if (!js_shell_rva_range_contains(nt, exports->AddressOfNames, (size_t)exports->NumberOfNames * sizeof(DWORD)) ||
        !js_shell_rva_range_contains(nt, exports->AddressOfNameOrdinals, (size_t)exports->NumberOfNames * sizeof(WORD)) ||
        !js_shell_rva_range_contains(nt, exports->AddressOfFunctions, (size_t)exports->NumberOfFunctions * sizeof(DWORD))) {
        js_shell_loader_fail("pe64 export name or function table is outside the mapped image");
        return 0;
    }
    DWORD *names = (DWORD *)js_shell_rva(image, exports->AddressOfNames);
    WORD *ordinals = (WORD *)js_shell_rva(image, exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)js_shell_rva(image, exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        if (!js_shell_rva_range_contains(nt, names[i], 1)) {
            js_shell_loader_fail("pe64 export name is outside the mapped image");
            return 0;
        }
        const char *export_name = (const char *)js_shell_rva(image, names[i]);
        if (!js_shell_image_cstring_contains(image, nt, export_name)) {
            js_shell_loader_fail("pe64 export name is outside the mapped image");
            return 0;
        }
        if (strcmp(export_name, name) != 0) continue;
        WORD ordinal = ordinals[i];
        if (ordinal >= exports->NumberOfFunctions) return 0;
        if (!js_shell_rva_range_contains(nt, functions[ordinal], 1)) {
            js_shell_loader_fail("pe64 export symbol address is outside the mapped image");
            return 0;
        }
        return js_shell_rva(image, functions[ordinal]);
    }
    return 0;
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
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || !js_shell_validate_range((size_t)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64), size)) {
        js_shell_loader_fail("pe64 DOS/NT headers are invalid");
        return 0;
    }
    const IMAGE_NT_HEADERS64 *nt_src = (const IMAGE_NT_HEADERS64 *)(bytes + dos->e_lfanew);
    if (nt_src->Signature != IMAGE_NT_SIGNATURE || nt_src->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt_src->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        js_shell_loader_fail("pe64 payload is not a supported AMD64 PE image");
        return 0;
    }
    if (!(nt_src->FileHeader.Characteristics & IMAGE_FILE_DLL) || nt_src->OptionalHeader.SizeOfImage == 0) {
        js_shell_loader_fail("pe64 payload is not a DLL image");
        return 0;
    }
    if (!js_shell_validate_range((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64), (size_t)nt_src->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), size)) {
        js_shell_loader_fail("pe64 section table is out of range");
        return 0;
    }

    void *image = VirtualAlloc(0, nt_src->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image) {
        js_shell_loader_fail("pe64 VirtualAlloc failed");
        return 0;
    }
    size_t header_size = nt_src->OptionalHeader.SizeOfHeaders;
    if (header_size > size) header_size = size;
    memcpy(image, bytes, header_size);
    js_shell_loader_trace("mapped headers");
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((unsigned char *)image + dos->e_lfanew);
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData == 0) continue;
        if (!js_shell_validate_range(section[i].PointerToRawData, section[i].SizeOfRawData, size)) {
            VirtualFree(image, 0, MEM_RELEASE);
            js_shell_loader_fail("pe64 section raw data is out of range");
            return 0;
        }
        DWORD virtual_size = section[i].Misc.VirtualSize ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
        if (section[i].VirtualAddress > nt->OptionalHeader.SizeOfImage || virtual_size > nt->OptionalHeader.SizeOfImage - section[i].VirtualAddress) {
            VirtualFree(image, 0, MEM_RELEASE);
            js_shell_loader_fail("pe64 section virtual range is out of image bounds");
            return 0;
        }
        DWORD copy_size = section[i].SizeOfRawData < virtual_size ? section[i].SizeOfRawData : virtual_size;
        memcpy((unsigned char *)image + section[i].VirtualAddress, bytes + section[i].PointerToRawData, copy_size);
    }

    uintptr_t delta = (uintptr_t)image - (uintptr_t)nt->OptionalHeader.ImageBase;
    if (!js_shell_apply_relocations(image, nt, delta) || !js_shell_resolve_imports(image, nt)) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    js_shell_loader_trace("relocated imports");

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD old_protect = 0;
        if (section[i].Misc.VirtualSize == 0) continue;
        VirtualProtect((unsigned char *)image + section[i].VirtualAddress, section[i].Misc.VirtualSize, js_shell_section_protect(section[i].Characteristics), &old_protect);
    }
    FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage);
    js_shell_loader_trace("protected sections");
    uintptr_t exec_low = 0;
    uintptr_t exec_high = 0;
    if (!js_shell_plan_executable_bounds(image, nt, &exec_low, &exec_high)) {
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
    if (!js_shell_validate_tls_callbacks(image, nt, exec_low, exec_high, &tls_callbacks)) {
        VirtualFree(image, 0, MEM_RELEASE);
        return 0;
    }
    js_shell_run_tls_callbacks(image, tls_callbacks, DLL_PROCESS_ATTACH);
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

    out_image->jni_on_load = (jint (*)(JavaVM *, void *))js_shell_find_export(image, nt, "JNI_OnLoad");
    out_image->native_abi_table_v1 = (const js_native_abi_table *(*)(void))js_shell_find_export(image, nt, "js_native_abi_table_v1");
    /* The manually mapped inner PE is not registered with the OS loader. Keep
     * unload detached from JVM shutdown so native method/code pages and CRT
     * teardown state remain process-lifetime. */
    out_image->jni_on_unload = 0;
    if (!out_image->jni_on_load) {
        VirtualFree(image, 0, MEM_RELEASE);
        js_shell_loader_fail("pe64 payload does not export JNI_OnLoad");
        return 0;
    }
    if (!out_image->native_abi_table_v1) {
        VirtualFree(image, 0, MEM_RELEASE);
        js_shell_loader_fail("pe64 payload does not export native ABI table");
        return 0;
    }
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
