#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "js_protected_section.h"
#include "js_crypto.h"

#include <stdint.h>
#include <string.h>

#if JS_PROTECTED_SECTION_ENABLED
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <dlfcn.h>
#include <elf.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#endif

/* Marker lives in .data so the build-time packer can find and flip it after
 * encrypting the .jsx section. */
__attribute__((used))
static volatile js_protected_seal js_protected_seal_marker = {
    { 0x4A, 0x53, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x31 }, /* "JSXSEAL1" */
    0u,
    0u,
    0u,
};

static void js_protected_section_xor(unsigned char *buf, unsigned int len) {
    int key_len = 0;
    const unsigned char *key = js_protected_section_key(&key_len);
    if (!key || key_len <= 0) return;
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
        js_sha256_update(&ctx, key, key_len);
        js_sha256_update(&ctx, ctr, 4);
        js_sha256_final(&ctx, block);
        unsigned int chunk = (len - produced) < 32u ? (len - produced) : 32u;
        for (unsigned int i = 0; i < chunk; i++) buf[produced + i] ^= block[i];
        js_vbc4_wipe_volatile(block, sizeof(block));
        produced += chunk;
        counter++;
    }
}

#if JS_PROTECTED_SECTION_ENABLED
#if defined(_WIN32)
JS_HIDDEN void js_protected_section_unseal_now(void) {
    unsigned char *marker_addr = (unsigned char*)&js_protected_seal_marker;
    if (js_protected_seal_marker.state != 1u) return;

    HMODULE module = NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)marker_addr, &module) || !module) {
        MEMORY_BASIC_INFORMATION mbi;
        memset(&mbi, 0, sizeof(mbi));
        if (!VirtualQuery(marker_addr, &mbi, sizeof(mbi)) || !mbi.AllocationBase) return;
        module = (HMODULE)mbi.AllocationBase;
    }
    unsigned char *base = (unsigned char*)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, JS_PROTECTED_SECTION_NAME, 4) == 0) {
            unsigned char *sec_base = base + sec[i].VirtualAddress;
            DWORD vsize = sec[i].Misc.VirtualSize;
            DWORD raw_size = sec[i].SizeOfRawData;
            unsigned int enc_len = (unsigned int)(vsize < raw_size ? vsize : raw_size);
            if (enc_len == 0) return;
            DWORD old_prot = 0;
            if (!VirtualProtect(sec_base, vsize ? vsize : enc_len, PAGE_EXECUTE_READWRITE, &old_prot)) return;
            js_protected_section_xor(sec_base, enc_len);
            js_protected_seal_marker.state = 0u;
            DWORD tmp = 0;
            VirtualProtect(sec_base, vsize ? vsize : enc_len, old_prot ? old_prot : PAGE_EXECUTE_READ, &tmp);
            FlushInstructionCache(GetCurrentProcess(), sec_base, vsize ? vsize : enc_len);
            return;
        }
    }
}

__attribute__((constructor))
static void js_protected_section_unseal(void) {
    js_protected_section_unseal_now();
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

    js_linux_map_range ranges[512];
    int count = 0;
    char line[512];
    while (count < (int)(sizeof(ranges) / sizeof(ranges[0])) && fgets(line, sizeof(line), maps)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[5] = { 0, 0, 0, 0, 0 };
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) == 3 && end > start) {
            ranges[count].start = (uintptr_t)start;
            ranges[count].end = (uintptr_t)end;
            ranges[count].readable = perms[0] == 'r';
            count++;
        }
    }
    fclose(maps);

    int marker_index = js_linux_find_map_index(ranges, count, marker_addr);
    if (marker_index < 0 || !ranges[marker_index].readable) return 0;

    uintptr_t low = ranges[marker_index].start;
    uintptr_t high = ranges[marker_index].end;
    for (int i = marker_index - 1; i >= 0 && ranges[i].end == low && ranges[i].readable; i--) low = ranges[i].start;
    for (int i = marker_index + 1; i < count && ranges[i].start == high && ranges[i].readable; i++) high = ranges[i].end;

    long page_size_long = sysconf(_SC_PAGESIZE);
    uintptr_t page_size = page_size_long > 0 ? (uintptr_t)page_size_long : 4096u;
    uintptr_t scan = marker_addr & ~(page_size - 1u);
    uintptr_t lowest_scan = low;
    const uintptr_t max_back_scan = (uintptr_t)256u * 1024u * 1024u;
    if (scan > max_back_scan && scan - max_back_scan > lowest_scan) lowest_scan = scan - max_back_scan;

    while (scan >= lowest_scan) {
        if (js_linux_is_readable_range(ranges, count, scan, scan + sizeof(Elf64_Ehdr))) {
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
                        js_linux_is_readable_range(ranges, count, ph_start, ph_end) &&
                        js_linux_find_map_index(ranges, count, section_start) >= 0 &&
                        section_end <= high) {
                    return (unsigned char *)scan;
                }
            }
        }
        if (scan < page_size) break;
        scan -= page_size;
    }
    return 0;
}

JS_HIDDEN void js_protected_section_unseal_now(void) {
    if (js_protected_seal_marker.state != 1u) return;
    if (js_protected_seal_marker.section_rva == 0u || js_protected_seal_marker.section_size == 0u) return;

    Dl_info info;
    memset(&info, 0, sizeof(info));
    unsigned char *image_base = 0;
    if (dladdr((const void*)&js_protected_seal_marker, &info) && info.dli_fbase) {
        image_base = (unsigned char*)info.dli_fbase;
    } else {
        image_base = js_linux_find_manual_elf_base(
            (uintptr_t)&js_protected_seal_marker,
            js_protected_seal_marker.section_rva,
            js_protected_seal_marker.section_size);
    }
    if (!image_base) return;

    unsigned char *sec_base = image_base + js_protected_seal_marker.section_rva;
    unsigned int enc_len = js_protected_seal_marker.section_size;
    long page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) return;
    uintptr_t page_size = (uintptr_t)page_size_long;
    uintptr_t sec_start = (uintptr_t)sec_base;
    uintptr_t page_start = sec_start & ~(page_size - 1u);
    uintptr_t sec_end = sec_start + (uintptr_t)enc_len;
    size_t prot_len = (size_t)((sec_end + page_size - 1u) - page_start);
    prot_len &= (size_t)~(page_size - 1u);
    if (prot_len == 0) return;

    if (mprotect((void*)page_start, prot_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return;
    js_protected_section_xor(sec_base, enc_len);
    js_protected_seal_marker.state = 0u;
    (void)mprotect((void*)page_start, prot_len, PROT_READ | PROT_EXEC);
#if defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache((char*)sec_base, (char*)(sec_base + enc_len));
#endif
}

__attribute__((constructor))
static void js_protected_section_unseal(void) {
    js_protected_section_unseal_now();
}
#endif
#else
JS_HIDDEN void js_protected_section_unseal_now(void) {}
#endif
