#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "js_protected_section.h"
#include "js_crypto.h"
#define JS_PROTECTED_SECTION_IMPLEMENTATION 1
#include "native_secrets.inc"
#undef JS_PROTECTED_SECTION_IMPLEMENTATION

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if JS_PROTECTED_SECTION_ENABLED
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <dlfcn.h>
#include <elf.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#endif

/* Marker lives in .data so the build-time packer can find it and initialize
 * SEALED + section coordinates after encrypting the .jsx body. */
__attribute__((used))
static volatile js_protected_seal js_protected_seal_marker = {
    { 0x4A, 0x53, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x31 }, /* "JSXSEAL1" */
    JS_PROTECTED_SECTION_OPEN,
    0u,
    0u,
};

typedef struct js_protected_region {
    unsigned char *code;
    unsigned int code_len;
    void *protect_base;
    size_t protect_len;
} js_protected_region;

static js_protected_region js_protected_runtime_region;
static volatile unsigned int js_protected_runtime_refs = 0u;
static volatile int js_protected_runtime_lock = 0;

static void js_protected_lock(void) {
#if defined(_MSC_VER) && defined(_WIN32)
    while (InterlockedCompareExchange((volatile LONG *)&js_protected_runtime_lock, 1, 0) != 0) SwitchToThread();
#else
    while (__atomic_exchange_n(&js_protected_runtime_lock, 1, __ATOMIC_ACQUIRE) != 0) {
#if defined(_WIN32)
        SwitchToThread();
#elif defined(__linux__) || defined(__ANDROID__)
        sched_yield();
#endif
    }
#endif
}

static void js_protected_unlock(void) {
#if defined(_MSC_VER) && defined(_WIN32)
    InterlockedExchange((volatile LONG *)&js_protected_runtime_lock, 0);
#else
    __atomic_store_n(&js_protected_runtime_lock, 0, __ATOMIC_RELEASE);
#endif
}

/*
 * The build-specific protected-section key program is data, not generated
 * executable code.  Production material lives in the dedicated read-only,
 * non-executable .jskd section and is read through volatile objects so the
 * optimizer cannot fold the per-build lane layout back into ordinary .text.
 */
static int js_protected_copy_scoped_key(unsigned char out[32]) {
#ifndef JS_PROTECTED_SECTION_KEY_PARTITIONS_GENERATED
    if (out) js_vbc4_wipe_volatile(out, 32u);
    return 0;
#else
    unsigned char seen[6] = { 0u, 0u, 0u, 0u, 0u, 0u };
    unsigned int version;
    unsigned int lane_count;
    unsigned int rotate_right;
    unsigned int profile_mask;
    if (!out) return 0;
    version = (unsigned int)js_protected_key_program_header[0];
    lane_count = (unsigned int)js_protected_key_program_header[1];
    rotate_right = (unsigned int)js_protected_key_program_header[2];
    profile_mask = (unsigned int)js_protected_key_program_header[3];
    if (version != 1u || lane_count < 3u || lane_count > 6u || rotate_right == 0u || rotate_right >= 8u) {
        goto failure;
    }
    for (unsigned int execution_index = 0u; execution_index < lane_count; execution_index++) {
        unsigned int lane = (unsigned int)js_protected_key_lane_order[execution_index];
        unsigned int width;
        unsigned int stride;
        unsigned int index_offset;
        unsigned int data_begin;
        unsigned int data_end;
        if (lane >= lane_count || seen[lane]) goto failure;
        seen[lane] = 1u;
        width = (unsigned int)js_protected_key_lane_widths[lane];
        stride = (unsigned int)js_protected_key_lane_strides[lane];
        index_offset = (unsigned int)js_protected_key_lane_index_offsets[lane];
        data_begin = (unsigned int)js_protected_key_lane_data_offsets[lane];
        data_end = (unsigned int)js_protected_key_lane_data_offsets[lane + 1u];
        if (width == 0u || stride == 0u || stride >= width || index_offset >= width ||
                data_end < data_begin || data_end - data_begin != width ||
                data_end > (unsigned int)sizeof(js_protected_key_lane_data)) {
            goto failure;
        }
    }
    for (unsigned int key_index = 0u; key_index < 32u; key_index++) {
        unsigned int value =
            (unsigned int)js_protected_key_lane_mask[(key_index * 7u + 3u) & 31u] ^ profile_mask;
        for (unsigned int execution_index = 0u; execution_index < lane_count; execution_index++) {
            unsigned int lane = (unsigned int)js_protected_key_lane_order[execution_index];
            unsigned int width = (unsigned int)js_protected_key_lane_widths[lane];
            unsigned int stored_index =
                (key_index * (unsigned int)js_protected_key_lane_strides[lane] +
                    (unsigned int)js_protected_key_lane_index_offsets[lane]) % width;
            unsigned int data_index =
                (unsigned int)js_protected_key_lane_data_offsets[lane] + stored_index;
            value ^= (unsigned int)js_protected_key_lane_data[data_index];
        }
        out[key_index] = (unsigned char)((value >> rotate_right) | (value << (8u - rotate_right)));
    }
    js_vbc4_wipe_volatile(seen, sizeof(seen));
    return 1;

failure:
    js_vbc4_wipe_volatile(seen, sizeof(seen));
    js_vbc4_wipe_volatile(out, 32u);
    return 0;
#endif
}

static int js_protected_plaintext_binding_matches(const unsigned char *buf, unsigned int len) {
#ifndef JS_PROTECTED_SECTION_KEY_PARTITIONS_GENERATED
    (void)buf;
    (void)len;
    return 0;
#else
    static const unsigned char expected_magic[8] = {
        0xD7u, 0x4Bu, 0x91u, 0x2Eu, 0xC3u, 0x58u, 0xA6u, 0x7Du
    };
    unsigned char digest[32];
    unsigned int diff = 0u;
    js_sha256_ctx ctx;
    if (!buf || len == 0u || len > (unsigned int)INT_MAX) return 0;
    for (unsigned int i = 0u; i < sizeof(expected_magic); i++) {
        diff |= (unsigned int)(js_protected_key_plaintext_binding[i] ^ expected_magic[i]);
    }
    if (diff != 0u) return 0;
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, buf, (int)len);
    js_sha256_final(&ctx, digest);
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    diff = 0u;
    for (unsigned int i = 0u; i < sizeof(digest); i++) {
        diff |= (unsigned int)(digest[i] ^ js_protected_key_plaintext_binding[sizeof(expected_magic) + i]);
    }
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return diff == 0u;
#endif
}

static int js_protected_section_xor(unsigned char *buf, unsigned int len) {
    unsigned char key[32];
    if (!buf || len == 0u) return 0;
    if (!JS_PROTECTED_COPY_SCOPED_KEY(key)) return 0;
    unsigned int produced = 0;
    unsigned int counter = 0;
    while (produced < len) {
        unsigned char block[32];
        unsigned char ctr[4];
        js_sha256_ctx ctx;
        ctr[0] = (unsigned char)(counter & 0xFF);
        ctr[1] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[3] = (unsigned char)((counter >> 24) & 0xFF);
        js_sha256_init(&ctx);
        js_sha256_update(&ctx, key, (int)sizeof(key));
        js_sha256_update(&ctx, ctr, 4);
        js_sha256_final(&ctx, block);
        js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
        unsigned int chunk = (len - produced) < 32u ? (len - produced) : 32u;
        for (unsigned int i = 0; i < chunk; i++) buf[produced + i] ^= block[i];
        js_vbc4_wipe_volatile(block, sizeof(block));
        produced += chunk;
        counter++;
    }
    js_vbc4_wipe_volatile(key, sizeof(key));
    return 1;
}

#if JS_PROTECTED_SECTION_ENABLED
#if defined(_WIN32)
static int js_protected_locate_region(void) {
    if (js_protected_runtime_region.code) return 1;
    unsigned char *marker_addr = (unsigned char *)&js_protected_seal_marker;
    HMODULE module = NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)marker_addr, &module) || !module) {
        MEMORY_BASIC_INFORMATION mbi;
        memset(&mbi, 0, sizeof(mbi));
        if (!VirtualQuery(marker_addr, &mbi, sizeof(mbi)) || !mbi.AllocationBase) return 0;
        module = (HMODULE)mbi.AllocationBase;
    }
    unsigned char *base = (unsigned char *)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, JS_PROTECTED_SECTION_NAME, 4) != 0) continue;
        DWORD vsize = sec[i].Misc.VirtualSize;
        DWORD raw_size = sec[i].SizeOfRawData;
        unsigned int enc_len = (unsigned int)(vsize < raw_size ? vsize : raw_size);
        if (enc_len == 0u || sec[i].VirtualAddress != js_protected_seal_marker.section_rva ||
                enc_len != js_protected_seal_marker.section_size) return 0;
        js_protected_runtime_region.code = base + sec[i].VirtualAddress;
        js_protected_runtime_region.code_len = enc_len;
        js_protected_runtime_region.protect_base = js_protected_runtime_region.code;
        js_protected_runtime_region.protect_len = (size_t)(vsize ? vsize : enc_len);
        return 1;
    }
    return 0;
}

static int js_protected_set_write(void) {
    DWORD old_protect = 0;
    return VirtualProtect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PAGE_READWRITE,
        &old_protect) != 0;
}

static int js_protected_set_execute(void) {
    DWORD old_protect = 0;
    return VirtualProtect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PAGE_EXECUTE_READ,
        &old_protect) != 0;
}

static int js_protected_set_sealed(void) {
    DWORD old_protect = 0;
    return VirtualProtect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PAGE_READONLY,
        &old_protect) != 0;
}

static int js_protected_set_disabled(void) {
    DWORD old_protect = 0;
    return VirtualProtect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PAGE_NOACCESS,
        &old_protect) != 0;
}

static void js_protected_flush(void) {
    FlushInstructionCache(
        GetCurrentProcess(),
        js_protected_runtime_region.code,
        js_protected_runtime_region.code_len);
}
#elif defined(__linux__) || defined(__ANDROID__)
typedef struct js_linux_map_range {
    uintptr_t start;
    uintptr_t end;
    int readable;
} js_linux_map_range;

static int js_linux_find_map_index(const js_linux_map_range *ranges, int count, uintptr_t address) {
    for (int i = 0; i < count; i++) {
        if (address >= ranges[i].start && address < ranges[i].end) return i;
    }
    return -1;
}

static int js_linux_is_readable_range(const js_linux_map_range *ranges, int count, uintptr_t start, uintptr_t end) {
    if (end <= start) return 0;
    uintptr_t cursor = start;
    while (cursor < end) {
        int index = js_linux_find_map_index(ranges, count, cursor);
        if (index < 0 || !ranges[index].readable || ranges[index].end <= cursor) return 0;
        cursor = ranges[index].end < end ? ranges[index].end : end;
    }
    return 1;
}

static unsigned char *js_linux_find_manual_elf_base(uintptr_t marker_addr, unsigned int section_rva, unsigned int section_size) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    size_t capacity = 256u;
    size_t count = 0u;
    js_linux_map_range *ranges = (js_linux_map_range *)malloc(capacity * sizeof(*ranges));
    if (!ranges) {
        fclose(maps);
        return 0;
    }
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[5] = { 0, 0, 0, 0, 0 };
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) == 3 && end > start) {
            if (count == capacity) {
                if (capacity > SIZE_MAX / 2u || capacity * 2u > SIZE_MAX / sizeof(*ranges)) {
                    free(ranges);
                    fclose(maps);
                    return 0;
                }
                size_t next_capacity = capacity * 2u;
                js_linux_map_range *grown = (js_linux_map_range *)realloc(ranges, next_capacity * sizeof(*ranges));
                if (!grown) {
                    free(ranges);
                    fclose(maps);
                    return 0;
                }
                ranges = grown;
                capacity = next_capacity;
            }
            ranges[count].start = (uintptr_t)start;
            ranges[count].end = (uintptr_t)end;
            ranges[count].readable = perms[0] == 'r';
            count++;
        }
    }
    fclose(maps);
    if (count > (size_t)INT_MAX) {
        free(ranges);
        return 0;
    }
    int range_count = (int)count;
    int marker_index = js_linux_find_map_index(ranges, range_count, marker_addr);
    if (marker_index < 0 || !ranges[marker_index].readable) {
        free(ranges);
        return 0;
    }
    uintptr_t low = ranges[marker_index].start;
    uintptr_t high = ranges[marker_index].end;
    for (int i = marker_index - 1; i >= 0 && ranges[i].end == low && ranges[i].readable; i--) low = ranges[i].start;
    for (int i = marker_index + 1; i < range_count && ranges[i].start == high && ranges[i].readable; i++) high = ranges[i].end;
    long page_size_long = sysconf(_SC_PAGESIZE);
    uintptr_t page_size = page_size_long > 0 ? (uintptr_t)page_size_long : 4096u;
    uintptr_t scan = marker_addr & ~(page_size - 1u);
    uintptr_t lowest_scan = low;
    const uintptr_t max_back_scan = (uintptr_t)256u * 1024u * 1024u;
    if (scan > max_back_scan && scan - max_back_scan > lowest_scan) lowest_scan = scan - max_back_scan;
    while (scan >= lowest_scan) {
        if (js_linux_is_readable_range(ranges, range_count, scan, scan + sizeof(Elf64_Ehdr))) {
            const Elf64_Ehdr *eh = (const Elf64_Ehdr *)scan;
            if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
                    eh->e_ident[EI_CLASS] == ELFCLASS64 &&
                    eh->e_ident[EI_DATA] == ELFDATA2LSB &&
                    eh->e_type == ET_DYN &&
#if defined(__x86_64__)
                    eh->e_machine == EM_X86_64 &&
#elif defined(__aarch64__)
                    eh->e_machine == EM_AARCH64 &&
#endif
                    eh->e_phentsize == sizeof(Elf64_Phdr) && eh->e_phnum > 0) {
                uintptr_t ph_start = scan + (uintptr_t)eh->e_phoff;
                uintptr_t ph_end = ph_start + (uintptr_t)eh->e_phnum * sizeof(Elf64_Phdr);
                uintptr_t section_start = scan + (uintptr_t)section_rva;
                uintptr_t section_end = section_start + (uintptr_t)section_size;
                if (ph_end >= ph_start && section_end >= section_start &&
                        js_linux_is_readable_range(ranges, range_count, ph_start, ph_end) &&
                        js_linux_find_map_index(ranges, range_count, section_start) >= 0 &&
                        section_end <= high) {
                    free(ranges);
                    return (unsigned char *)scan;
                }
            }
        }
        if (scan < page_size) break;
        scan -= page_size;
    }
    free(ranges);
    return 0;
}

static int js_protected_locate_region(void) {
    if (js_protected_runtime_region.code) return 1;
    if (js_protected_seal_marker.section_rva == 0u || js_protected_seal_marker.section_size == 0u) return 0;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    unsigned char *image_base = 0;
    if (dladdr((const void *)&js_protected_seal_marker, &info) && info.dli_fbase) {
        image_base = (unsigned char *)info.dli_fbase;
    } else {
        image_base = js_linux_find_manual_elf_base(
            (uintptr_t)&js_protected_seal_marker,
            js_protected_seal_marker.section_rva,
            js_protected_seal_marker.section_size);
    }
    if (!image_base) return 0;
    unsigned char *sec_base = image_base + js_protected_seal_marker.section_rva;
    unsigned int enc_len = js_protected_seal_marker.section_size;
    long page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) return 0;
    uintptr_t page_size = (uintptr_t)page_size_long;
    uintptr_t sec_start = (uintptr_t)sec_base;
    uintptr_t page_start = sec_start & ~(page_size - 1u);
    uintptr_t sec_end = sec_start + (uintptr_t)enc_len;
    if (sec_end < sec_start) return 0;
    size_t prot_len = (size_t)((sec_end + page_size - 1u) - page_start);
    prot_len &= (size_t)~(page_size - 1u);
    if (prot_len == 0u) return 0;
    js_protected_runtime_region.code = sec_base;
    js_protected_runtime_region.code_len = enc_len;
    js_protected_runtime_region.protect_base = (void *)page_start;
    js_protected_runtime_region.protect_len = prot_len;
    return 1;
}

static int js_protected_set_write(void) {
    return mprotect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PROT_READ | PROT_WRITE) == 0;
}

static int js_protected_set_execute(void) {
    return mprotect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PROT_READ | PROT_EXEC) == 0;
}

static int js_protected_set_sealed(void) {
    return mprotect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PROT_READ) == 0;
}

static int js_protected_set_disabled(void) {
    return mprotect(
        js_protected_runtime_region.protect_base,
        js_protected_runtime_region.protect_len,
        PROT_NONE) == 0;
}

static void js_protected_flush(void) {
#if defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache(
        (char *)js_protected_runtime_region.code,
        (char *)(js_protected_runtime_region.code + js_protected_runtime_region.code_len));
#endif
}
#endif

static int js_protected_lifecycle_enabled(void) {
    return js_protected_seal_marker.section_rva != 0u && js_protected_seal_marker.section_size != 0u;
}

static void js_protected_mark_broken_locked(void) {
    js_protected_seal_marker.state = JS_PROTECTED_SECTION_BROKEN;
    if (js_protected_runtime_refs == 0u && js_protected_runtime_region.code) {
        (void)js_protected_set_disabled();
    }
}

static void js_protected_finish_broken_locked(void) {
    if (!js_protected_runtime_region.code) return;
    if (js_protected_set_write() &&
            js_protected_section_xor(js_protected_runtime_region.code, js_protected_runtime_region.code_len)) {
        js_protected_flush();
    }
    (void)js_protected_set_disabled();
}

static int js_protected_open_locked(void) {
    if (js_protected_seal_marker.state != JS_PROTECTED_SECTION_SEALED ||
            !js_protected_locate_region() || !js_protected_set_write()) {
        js_protected_mark_broken_locked();
        return 0;
    }
    if (!js_protected_section_xor(js_protected_runtime_region.code, js_protected_runtime_region.code_len)) {
        js_protected_mark_broken_locked();
        return 0;
    }
    if (!js_protected_plaintext_binding_matches(js_protected_runtime_region.code, js_protected_runtime_region.code_len)) {
        (void)js_protected_section_xor(js_protected_runtime_region.code, js_protected_runtime_region.code_len);
        js_protected_flush();
        js_protected_mark_broken_locked();
        return 0;
    }
    js_protected_flush();
    if (!js_protected_set_execute()) {
        if (js_protected_section_xor(js_protected_runtime_region.code, js_protected_runtime_region.code_len)) {
            js_protected_flush();
        }
        js_protected_mark_broken_locked();
        return 0;
    }
    js_protected_seal_marker.state = JS_PROTECTED_SECTION_OPEN;
    return 1;
}

static int js_protected_seal_locked(void) {
    if (js_protected_seal_marker.state != JS_PROTECTED_SECTION_OPEN ||
            !js_protected_runtime_region.code || !js_protected_set_write()) {
        js_protected_mark_broken_locked();
        return 0;
    }
    if (!js_protected_section_xor(js_protected_runtime_region.code, js_protected_runtime_region.code_len)) {
        js_protected_mark_broken_locked();
        return 0;
    }
    js_protected_flush();
    if (!js_protected_set_sealed()) {
        js_protected_mark_broken_locked();
        return 0;
    }
    js_protected_seal_marker.state = JS_PROTECTED_SECTION_SEALED;
    return 1;
}

JS_HIDDEN int js_protected_section_enter(void) {
    if (!js_protected_lifecycle_enabled()) {
        return js_protected_seal_marker.state != JS_PROTECTED_SECTION_BROKEN;
    }
    js_protected_lock();
    int ok = 1;
    if (js_protected_seal_marker.state == JS_PROTECTED_SECTION_BROKEN) {
        ok = 0;
    } else if (js_protected_runtime_refs == 0u) {
        ok = js_protected_open_locked();
    } else if (js_protected_seal_marker.state != JS_PROTECTED_SECTION_OPEN) {
        js_protected_mark_broken_locked();
        ok = 0;
    }
    if (ok) js_protected_runtime_refs++;
    js_protected_unlock();
    return ok;
}

JS_HIDDEN int js_protected_section_leave(void) {
    if (!js_protected_lifecycle_enabled()) {
        return js_protected_seal_marker.state != JS_PROTECTED_SECTION_BROKEN;
    }
    js_protected_lock();
    int ok = 1;
    if (js_protected_runtime_refs == 0u) {
        js_protected_mark_broken_locked();
        ok = 0;
    } else if (js_protected_seal_marker.state == JS_PROTECTED_SECTION_OPEN) {
        js_protected_runtime_refs--;
        if (js_protected_runtime_refs == 0u) ok = js_protected_seal_locked();
    } else {
        js_protected_mark_broken_locked();
        js_protected_runtime_refs--;
        if (js_protected_runtime_refs == 0u) js_protected_finish_broken_locked();
        ok = 0;
    }
    js_protected_unlock();
    return ok;
}

JS_HIDDEN unsigned int js_protected_section_state(void) {
    return js_protected_seal_marker.state;
}

JS_HIDDEN unsigned int js_protected_section_refcount(void) {
    return js_protected_runtime_refs;
}

__attribute__((constructor))
static void js_protected_section_prepare(void) {
    if (js_protected_seal_marker.state != JS_PROTECTED_SECTION_SEALED) return;
    js_protected_lock();
    if (!js_protected_locate_region() || !js_protected_set_sealed()) js_protected_mark_broken_locked();
    js_protected_unlock();
}
#else
JS_HIDDEN int js_protected_section_enter(void) { return 1; }
JS_HIDDEN int js_protected_section_leave(void) { return 1; }
JS_HIDDEN unsigned int js_protected_section_state(void) { return JS_PROTECTED_SECTION_OPEN; }
JS_HIDDEN unsigned int js_protected_section_refcount(void) { return 0u; }
#endif
