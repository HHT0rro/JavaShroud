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
__attribute__((constructor))
static void js_protected_section_unseal(void) {
    unsigned char *marker_addr = (unsigned char*)&js_protected_seal_marker;
    if (js_protected_seal_marker.state != 1u) return;

    HMODULE module = NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)marker_addr, &module) || !module) {
        return;
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
#elif defined(__linux__) || defined(__ANDROID__)
__attribute__((constructor))
static void js_protected_section_unseal(void) {
    if (js_protected_seal_marker.state != 1u) return;
    if (js_protected_seal_marker.section_rva == 0u || js_protected_seal_marker.section_size == 0u) return;

    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!dladdr((const void*)&js_protected_seal_marker, &info) || !info.dli_fbase) return;

    unsigned char *sec_base = (unsigned char*)info.dli_fbase + js_protected_seal_marker.section_rva;
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
#endif
#endif
