#include "js_shell_loader.h"

#if defined(__APPLE__) && defined(__MACH__)

#include <stdint.h>
#include <string.h>

#define JS_MH_MAGIC_64 0xfeedfacfu
#define JS_CPU_TYPE_X86_64 0x01000007u
#define JS_CPU_TYPE_ARM64 0x0100000cu
#define JS_MH_DYLIB 0x6u
#define JS_LC_SEGMENT_64 0x19u
#define JS_LC_DYLD_INFO 0x22u
#define JS_LC_DYLD_INFO_ONLY 0x80000022u
#define JS_LC_SYMTAB 0x2u
#define JS_LC_DYSYMTAB 0xbu
#define JS_LC_LOAD_DYLIB 0xcu
#define JS_LC_LOAD_WEAK_DYLIB 0x18u
#define JS_LC_REEXPORT_DYLIB 0x1fu
#define JS_LC_LOAD_UPWARD_DYLIB 0x23u
#define JS_LC_MAIN 0x80000028u
#define JS_SECTION_TYPE 0x000000ffu
#define JS_S_MOD_INIT_FUNC_POINTERS 0x9u

#define JS_REBASE_OPCODE_MASK 0xf0u
#define JS_REBASE_IMMEDIATE_MASK 0x0fu
#define JS_REBASE_OPCODE_DONE 0x00u
#define JS_REBASE_OPCODE_SET_TYPE_IMM 0x10u
#define JS_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x20u
#define JS_REBASE_OPCODE_ADD_ADDR_ULEB 0x30u
#define JS_REBASE_OPCODE_ADD_ADDR_IMM_SCALED 0x40u
#define JS_REBASE_OPCODE_DO_REBASE_IMM_TIMES 0x50u
#define JS_REBASE_OPCODE_DO_REBASE_ULEB_TIMES 0x60u
#define JS_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB 0x70u
#define JS_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80u

#define JS_BIND_OPCODE_MASK 0xf0u
#define JS_BIND_OPCODE_DONE 0x00u
#define JS_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM 0x10u
#define JS_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB 0x20u
#define JS_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM 0x30u
#define JS_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40u
#define JS_BIND_OPCODE_SET_TYPE_IMM 0x50u
#define JS_BIND_OPCODE_SET_ADDEND_SLEB 0x60u
#define JS_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x70u
#define JS_BIND_OPCODE_ADD_ADDR_ULEB 0x80u
#define JS_BIND_OPCODE_DO_BIND 0x90u
#define JS_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB 0xa0u
#define JS_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED 0xb0u
#define JS_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xc0u

typedef struct js_mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} js_mach_header_64;

typedef struct js_load_command {
    uint32_t cmd;
    uint32_t cmdsize;
} js_load_command;

typedef struct js_segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} js_segment_command_64;

typedef struct js_section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} js_section_64;

typedef struct js_dyld_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t rebase_off;
    uint32_t rebase_size;
    uint32_t bind_off;
    uint32_t bind_size;
    uint32_t weak_bind_off;
    uint32_t weak_bind_size;
    uint32_t lazy_bind_off;
    uint32_t lazy_bind_size;
    uint32_t export_off;
    uint32_t export_size;
} js_dyld_info_command;

typedef struct js_symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} js_symtab_command;

static const char *g_js_shell_loader_failure = "mach-o loader has not started";

static void js_shell_loader_fail(const char *reason) {
    g_js_shell_loader_failure = reason;
}

static int js_shell_validate_range(uint64_t offset, uint64_t size, uint64_t total) {
    return offset <= total && size <= total - offset;
}

static const unsigned char *js_shell_read_uleb128(const unsigned char *p, const unsigned char *end, uint64_t *out) {
    uint64_t value = 0;
    unsigned int shift = 0;
    while (p < end && shift < 64u) {
        unsigned char byte = *p++;
        value |= ((uint64_t)(byte & 0x7fu)) << shift;
        if ((byte & 0x80u) == 0) {
            *out = value;
            return p;
        }
        shift += 7u;
    }
    return 0;
}

static const unsigned char *js_shell_read_sleb128(const unsigned char *p, const unsigned char *end) {
    unsigned int shift = 0;
    while (p < end && shift < 64u) {
        unsigned char byte = *p++;
        if ((byte & 0x80u) == 0) return p;
        shift += 7u;
    }
    return 0;
}

static const unsigned char *js_shell_skip_cstring(const unsigned char *p, const unsigned char *end) {
    while (p < end) {
        if (*p++ == 0) return p;
    }
    return 0;
}

static int js_shell_validate_rebase_stream(const unsigned char *base, size_t size, unsigned int segment_count) {
    const unsigned char *p = base;
    const unsigned char *end = base + size;
    unsigned int saw_done = size == 0u;
    while (p < end) {
        unsigned char byte = *p++;
        unsigned char opcode = byte & JS_REBASE_OPCODE_MASK;
        unsigned char imm = byte & JS_REBASE_IMMEDIATE_MASK;
        uint64_t ignored = 0;
        if (opcode == JS_REBASE_OPCODE_DONE) { saw_done = 1; break; }
        if (opcode == JS_REBASE_OPCODE_SET_TYPE_IMM || opcode == JS_REBASE_OPCODE_ADD_ADDR_IMM_SCALED || opcode == JS_REBASE_OPCODE_DO_REBASE_IMM_TIMES) {
            (void)imm;
        } else if (opcode == JS_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
            if (imm >= segment_count) return 0;
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
        } else if (opcode == JS_REBASE_OPCODE_ADD_ADDR_ULEB || opcode == JS_REBASE_OPCODE_DO_REBASE_ULEB_TIMES || opcode == JS_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
        } else if (opcode == JS_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
        } else {
            return 0;
        }
    }
    return saw_done && p <= end;
}

static int js_shell_validate_bind_stream(const unsigned char *base, size_t size, unsigned int segment_count) {
    const unsigned char *p = base;
    const unsigned char *end = base + size;
    unsigned int saw_done = size == 0u;
    while (p < end) {
        unsigned char byte = *p++;
        unsigned char opcode = byte & JS_BIND_OPCODE_MASK;
        unsigned char imm = byte & 0x0fu;
        uint64_t ignored = 0;
        if (opcode == JS_BIND_OPCODE_DONE) { saw_done = 1; break; }
        if (opcode == JS_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM || opcode == JS_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM || opcode == JS_BIND_OPCODE_SET_TYPE_IMM || opcode == JS_BIND_OPCODE_DO_BIND || opcode == JS_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED) {
            (void)imm;
        } else if (opcode == JS_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB || opcode == JS_BIND_OPCODE_ADD_ADDR_ULEB || opcode == JS_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
        } else if (opcode == JS_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM) {
            p = js_shell_skip_cstring(p, end);
            if (!p) return 0;
        } else if (opcode == JS_BIND_OPCODE_SET_ADDEND_SLEB) {
            p = js_shell_read_sleb128(p, end);
            if (!p) return 0;
        } else if (opcode == JS_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
            if (imm >= segment_count) return 0;
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
        } else if (opcode == JS_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
        } else {
            return 0;
        }
    }
    return saw_done && p <= end;
}

static int js_shell_export_trie_has_symbol(const unsigned char *base, size_t size, const char *needle) {
    const unsigned char *end = base + size;
    const unsigned char *stack[96];
    size_t stack_count = 0;
    stack[stack_count++] = base;
    while (stack_count) {
        const unsigned char *node = stack[--stack_count];
        if (node < base || node >= end) return 0;
        uint64_t terminal_size = 0;
        const unsigned char *p = js_shell_read_uleb128(node, end, &terminal_size);
        if (!p || terminal_size > (uint64_t)(end - p)) return 0;
        p += terminal_size;
        if (p >= end) return 0;
        unsigned int child_count = *p++;
        for (unsigned int i = 0; i < child_count; i++) {
            const char *edge = (const char *)p;
            size_t edge_len = strnlen(edge, (size_t)(end - p));
            if (p + edge_len >= end) return 0;
            if (strcmp(edge, needle) == 0) return 1;
            p += edge_len + 1u;
            uint64_t child_offset = 0;
            p = js_shell_read_uleb128(p, end, &child_offset);
            if (!p || child_offset >= size) return 0;
            if (stack_count < sizeof(stack) / sizeof(stack[0])) stack[stack_count++] = base + child_offset;
        }
    }
    return 0;
}

int js_shell_load_inner_image(const js_shell_payload_view *payload, js_shell_loaded_image *out_image) {
    if (!payload || !out_image || !payload->decoded_payload || payload->decoded_payload_size < sizeof(js_mach_header_64)) {
        js_shell_loader_fail("mach-o payload is empty or missing decoded bytes");
        return 0;
    }
    memset(out_image, 0, sizeof(*out_image));
    const unsigned char *bytes = payload->decoded_payload;
    size_t size = payload->decoded_payload_size;
    const js_mach_header_64 *mh = (const js_mach_header_64 *)bytes;
    if (mh->magic != JS_MH_MAGIC_64) {
        js_shell_loader_fail("mach-o payload is not a 64-bit little-endian image");
        return 0;
    }
    if (mh->filetype != JS_MH_DYLIB || (mh->cputype != JS_CPU_TYPE_X86_64 && mh->cputype != JS_CPU_TYPE_ARM64)) {
        js_shell_loader_fail("mach-o payload is not a supported x64/arm64 dylib");
        return 0;
    }
    if (!js_shell_validate_range(sizeof(js_mach_header_64), mh->sizeofcmds, size)) {
        js_shell_loader_fail("mach-o load-command table is out of range");
        return 0;
    }

    const unsigned char *cmd_ptr = bytes + sizeof(js_mach_header_64);
    const unsigned char *cmd_end = cmd_ptr + mh->sizeofcmds;
    unsigned int segment_count = 0;
    int saw_text = 0;
    int saw_linkedit = 0;
    unsigned int initializer_section_count = 0;
    const js_dyld_info_command *dyld = 0;
    const js_symtab_command *symtab = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cmd_ptr + sizeof(js_load_command) > cmd_end) {
            js_shell_loader_fail("mach-o load command is truncated");
            return 0;
        }
        const js_load_command *lc = (const js_load_command *)cmd_ptr;
        if (lc->cmdsize < sizeof(js_load_command) || cmd_ptr + lc->cmdsize > cmd_end) {
            js_shell_loader_fail("mach-o load command size is invalid");
            return 0;
        }
        if (lc->cmd == JS_LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(js_segment_command_64)) {
                js_shell_loader_fail("mach-o segment command is truncated");
                return 0;
            }
            const js_segment_command_64 *seg = (const js_segment_command_64 *)cmd_ptr;
            if (!js_shell_validate_range(seg->fileoff, seg->filesize, size)) {
                js_shell_loader_fail("mach-o segment file range is out of bounds");
                return 0;
            }
            if (seg->nsects && lc->cmdsize < sizeof(js_segment_command_64) + ((uint64_t)seg->nsects * sizeof(js_section_64))) {
                js_shell_loader_fail("mach-o section table is truncated");
                return 0;
            }
            const js_section_64 *sections = (const js_section_64 *)(cmd_ptr + sizeof(js_segment_command_64));
            for (uint32_t si = 0; si < seg->nsects; si++) {
                const js_section_64 *section = sections + si;
                if (section->size && section->offset && !js_shell_validate_range(section->offset, section->size, size)) {
                    js_shell_loader_fail("mach-o section file range is out of bounds");
                    return 0;
                }
                if (section->nreloc && !js_shell_validate_range(section->reloff, (uint64_t)section->nreloc * 8u, size)) {
                    js_shell_loader_fail("mach-o relocation table is out of bounds");
                    return 0;
                }
                if ((section->flags & JS_SECTION_TYPE) == JS_S_MOD_INIT_FUNC_POINTERS) initializer_section_count++;
            }
            if (memcmp(seg->segname, "__TEXT", 6) == 0) saw_text = 1;
            if (memcmp(seg->segname, "__LINKEDIT", 10) == 0) saw_linkedit = 1;
            segment_count++;
        } else if (lc->cmd == JS_LC_DYLD_INFO || lc->cmd == JS_LC_DYLD_INFO_ONLY) {
            if (lc->cmdsize < sizeof(js_dyld_info_command)) {
                js_shell_loader_fail("mach-o dyld info command is truncated");
                return 0;
            }
            dyld = (const js_dyld_info_command *)cmd_ptr;
        } else if (lc->cmd == JS_LC_SYMTAB) {
            if (lc->cmdsize < sizeof(js_symtab_command)) {
                js_shell_loader_fail("mach-o symtab command is truncated");
                return 0;
            }
            symtab = (const js_symtab_command *)cmd_ptr;
        } else if (lc->cmd == JS_LC_LOAD_DYLIB || lc->cmd == JS_LC_LOAD_WEAK_DYLIB || lc->cmd == JS_LC_REEXPORT_DYLIB || lc->cmd == JS_LC_LOAD_UPWARD_DYLIB || lc->cmd == JS_LC_MAIN) {
            /* Presence is accepted here; bind/rebase execution remains fail-closed below. */
        }
        cmd_ptr += lc->cmdsize;
    }

    if (!segment_count || !saw_text || !saw_linkedit || !dyld) {
        js_shell_loader_fail("mach-o payload lacks required segments or dyld info");
        return 0;
    }
    if (!js_shell_validate_range(dyld->rebase_off, dyld->rebase_size, size) ||
        !js_shell_validate_range(dyld->bind_off, dyld->bind_size, size) ||
        !js_shell_validate_range(dyld->lazy_bind_off, dyld->lazy_bind_size, size) ||
        !js_shell_validate_range(dyld->export_off, dyld->export_size, size)) {
        js_shell_loader_fail("mach-o dyld info range is out of bounds");
        return 0;
    }
    if (symtab && (!js_shell_validate_range(symtab->symoff, (uint64_t)symtab->nsyms * 16u, size) || !js_shell_validate_range(symtab->stroff, symtab->strsize, size))) {
        js_shell_loader_fail("mach-o symbol table range is out of bounds");
        return 0;
    }
    if (!js_shell_validate_rebase_stream(bytes + dyld->rebase_off, dyld->rebase_size, segment_count) ||
        !js_shell_validate_bind_stream(bytes + dyld->bind_off, dyld->bind_size, segment_count) ||
        !js_shell_validate_bind_stream(bytes + dyld->lazy_bind_off, dyld->lazy_bind_size, segment_count)) {
        js_shell_loader_fail("mach-o rebase/bind/lazy-bind opcode stream is invalid");
        return 0;
    }
    if (initializer_section_count > 16u) {
        js_shell_loader_fail("mach-o initializer section count is suspicious");
        return 0;
    }
    if (!dyld->export_size || !js_shell_export_trie_has_symbol(bytes + dyld->export_off, dyld->export_size, "_JNI_OnLoad")) {
        js_shell_loader_fail("mach-o payload does not export _JNI_OnLoad");
        return 0;
    }
    if (!js_shell_export_trie_has_symbol(bytes + dyld->export_off, dyld->export_size, "_js_native_abi_table_v1")) {
        js_shell_loader_fail("mach-o payload does not export native ABI table");
        return 0;
    }

    js_shell_loader_fail("mach-o payload validated through segments, sections, rebase/bind/lazy-bind streams and initializer metadata, but anonymous execution mapping stays fail-closed until runtime execution is verified on macOS");
    return 0;
}

void js_shell_unload_inner_image(js_shell_loaded_image *image) { (void)image; }
const char *js_shell_loader_failure_reason(void) { return g_js_shell_loader_failure; }

#endif
