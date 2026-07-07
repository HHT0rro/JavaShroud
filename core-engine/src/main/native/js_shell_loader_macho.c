#include "js_shell_loader.h"

#if defined(__APPLE__) && defined(__MACH__)

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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
#define JS_VM_PROT_READ 0x1u
#define JS_VM_PROT_WRITE 0x2u
#define JS_VM_PROT_EXECUTE 0x4u
#define JS_MACHO_MAX_SEGMENTS 64u
#define JS_MACHO_MAX_INITIALIZER_SECTIONS 16u
#define JS_MACHO_PAGE_GRANULE 0x4000ull

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

typedef struct js_macho_segment_plan {
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t initprot;
    int executable;
} js_macho_segment_plan;

typedef struct js_macho_initializer_section_plan {
    uint64_t vmaddr;
    uint64_t size;
} js_macho_initializer_section_plan;

typedef struct js_macho_image_plan {
    js_macho_segment_plan segments[JS_MACHO_MAX_SEGMENTS];
    js_macho_initializer_section_plan initializer_sections[JS_MACHO_MAX_INITIALIZER_SECTIONS];
    unsigned int segment_count;
    unsigned int initializer_section_count;
    uint64_t vm_low;
    uint64_t vm_high;
    uint64_t mapping_size;
    uint64_t text_low;
    uint64_t text_high;
    uint64_t slide;
} js_macho_image_plan;

static const char *g_js_shell_loader_failure = "mach-o loader has not started";
static volatile const char g_js_shell_macho_fail_closed_marker[] = "JS_MACHO_ANON_EXEC_FAIL_CLOSED_V1";

static void js_shell_loader_fail(const char *reason) {
    g_js_shell_loader_failure = reason;
}

static const unsigned char *js_shell_read_uleb128(const unsigned char *p, const unsigned char *end, uint64_t *out);
static int js_shell_macho_range_inside_mapping(const js_macho_image_plan *plan, uint64_t vmaddr, uint64_t size);

static int js_shell_validate_range(uint64_t offset, uint64_t size, uint64_t total) {
    return offset <= total && size <= total - offset;
}

static uint64_t js_shell_macho_align_down(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1u);
}

static int js_shell_macho_align_up(uint64_t value, uint64_t alignment, uint64_t *out) {
    uint64_t mask = alignment - 1u;
    if (value > UINT64_MAX - mask) return 0;
    *out = (value + mask) & ~mask;
    return 1;
}

static int js_shell_macho_add_overflows(uint64_t left, uint64_t right, uint64_t *out) {
    if (left > UINT64_MAX - right) return 1;
    *out = left + right;
    return 0;
}

static void js_shell_macho_init_image_plan(js_macho_image_plan *plan) {
    memset(plan, 0, sizeof(*plan));
    plan->vm_low = UINT64_MAX;
}

static int js_shell_macho_plan_segment(js_macho_image_plan *plan, const js_segment_command_64 *seg, size_t payload_size) {
    uint64_t vm_end = 0;
    uint64_t aligned_high = 0;
    if (plan->segment_count >= JS_MACHO_MAX_SEGMENTS) {
        js_shell_loader_fail("mach-o segment count exceeds loader planning table");
        return 0;
    }
    if (!seg->vmsize || seg->filesize > seg->vmsize) {
        js_shell_loader_fail("mach-o segment vm/file size is invalid for anonymous mapping");
        return 0;
    }
    if (js_shell_macho_add_overflows(seg->vmaddr, seg->vmsize, &vm_end)) {
        js_shell_loader_fail("mach-o segment vm range overflows");
        return 0;
    }
    if (!js_shell_validate_range(seg->fileoff, seg->filesize, payload_size)) {
        js_shell_loader_fail("mach-o segment file range is out of bounds");
        return 0;
    }

    js_macho_segment_plan *entry = &plan->segments[plan->segment_count++];
    entry->vmaddr = seg->vmaddr;
    entry->vmsize = seg->vmsize;
    entry->fileoff = seg->fileoff;
    entry->filesize = seg->filesize;
    entry->initprot = seg->initprot;
    entry->executable = (seg->initprot & JS_VM_PROT_EXECUTE) != 0;

    uint64_t aligned_low = js_shell_macho_align_down(seg->vmaddr, JS_MACHO_PAGE_GRANULE);
    if (!js_shell_macho_align_up(vm_end, JS_MACHO_PAGE_GRANULE, &aligned_high)) {
        js_shell_loader_fail("mach-o aligned segment range overflows");
        return 0;
    }
    if (aligned_low < plan->vm_low) plan->vm_low = aligned_low;
    if (aligned_high > plan->vm_high) plan->vm_high = aligned_high;
    if (entry->executable) {
        if (!plan->text_high || aligned_low < plan->text_low) plan->text_low = aligned_low;
        if (aligned_high > plan->text_high) plan->text_high = aligned_high;
    }
    return 1;
}

static int js_shell_macho_plan_initializer_section(js_macho_image_plan *plan, const js_section_64 *section) {
    if (plan->initializer_section_count >= JS_MACHO_MAX_INITIALIZER_SECTIONS) {
        js_shell_loader_fail("mach-o initializer section count is suspicious");
        return 0;
    }
    if ((section->size % sizeof(uint64_t)) != 0 || !js_shell_macho_range_inside_mapping(plan, section->addr, section->size)) {
        js_shell_loader_fail("mach-o initializer pointer section is outside anonymous mapping");
        return 0;
    }
    js_macho_initializer_section_plan *entry = &plan->initializer_sections[plan->initializer_section_count++];
    entry->vmaddr = section->addr;
    entry->size = section->size;
    return 1;
}

static int js_shell_macho_finalize_image_plan(js_macho_image_plan *plan) {
    if (!plan->segment_count || plan->vm_low == UINT64_MAX || plan->vm_high <= plan->vm_low) {
        js_shell_loader_fail("mach-o anonymous image layout has no mapped segments");
        return 0;
    }
    plan->mapping_size = plan->vm_high - plan->vm_low;
    plan->slide = 0u - plan->vm_low;
    if (!plan->text_high || plan->text_high <= plan->text_low) {
        js_shell_loader_fail("mach-o anonymous image layout has no executable segment");
        return 0;
    }
    return 1;
}

static int js_shell_macho_mmap_prot(uint32_t initprot) {
    int prot = 0;
    if (initprot & JS_VM_PROT_READ) prot |= PROT_READ;
    if (initprot & JS_VM_PROT_WRITE) prot |= PROT_WRITE;
    if (initprot & JS_VM_PROT_EXECUTE) prot |= PROT_EXEC;
    return prot ? prot : PROT_NONE;
}

static int js_shell_macho_range_inside_mapping(const js_macho_image_plan *plan, uint64_t vmaddr, uint64_t size) {
    uint64_t end = 0;
    if (js_shell_macho_add_overflows(vmaddr, size, &end)) return 0;
    return vmaddr >= plan->vm_low && end <= plan->vm_high;
}

static int js_shell_macho_materialize_segments(const unsigned char *bytes, const js_macho_image_plan *plan, void **mapping_out) {
    void *mapping = mmap(0, (size_t)plan->mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED) {
        js_shell_loader_fail("mach-o anonymous image mmap failed");
        return 0;
    }
    for (unsigned int i = 0; i < plan->segment_count; i++) {
        const js_macho_segment_plan *seg = &plan->segments[i];
        if (!js_shell_macho_range_inside_mapping(plan, seg->vmaddr, seg->vmsize)) {
            munmap(mapping, (size_t)plan->mapping_size);
            js_shell_loader_fail("mach-o planned segment is outside anonymous mapping");
            return 0;
        }
        if (seg->filesize) {
            uint64_t target_offset = seg->vmaddr - plan->vm_low;
            memcpy((unsigned char *)mapping + target_offset, bytes + seg->fileoff, (size_t)seg->filesize);
        }
    }
    *mapping_out = mapping;
    return 1;
}

static int js_shell_macho_validate_initializers(void *mapping, const js_macho_image_plan *plan) {
    uint64_t executable_low = 0;
    uint64_t executable_high = 0;
    if (js_shell_macho_add_overflows(plan->text_low, plan->slide, &executable_low) ||
        js_shell_macho_add_overflows(plan->text_high, plan->slide, &executable_high)) {
        js_shell_loader_fail("mach-o initializer executable bounds overflow");
        return 0;
    }
    for (unsigned int si = 0; si < plan->initializer_section_count; si++) {
        const js_macho_initializer_section_plan *section = &plan->initializer_sections[si];
        if (!js_shell_macho_range_inside_mapping(plan, section->vmaddr, section->size) || (section->size % sizeof(uint64_t)) != 0) {
            js_shell_loader_fail("mach-o initializer pointer section is outside anonymous mapping");
            return 0;
        }
        const uint64_t *entries = (const uint64_t *)((const unsigned char *)mapping + (section->vmaddr - plan->vm_low));
        size_t count = (size_t)(section->size / sizeof(uint64_t));
        for (size_t i = 0; i < count; i++) {
            uint64_t initializer = entries[i];
            if (initializer < executable_low || initializer >= executable_high) {
                js_shell_loader_fail("mach-o initializer pointer is outside executable image pages");
                return 0;
            }
        }
    }
    return 1;
}

static int js_shell_macho_protect_segments(void *mapping, const js_macho_image_plan *plan) {
    for (unsigned int i = 0; i < plan->segment_count; i++) {
        const js_macho_segment_plan *seg = &plan->segments[i];
        uint64_t segment_low = js_shell_macho_align_down(seg->vmaddr, JS_MACHO_PAGE_GRANULE);
        uint64_t segment_end = 0;
        uint64_t segment_high = 0;
        if (js_shell_macho_add_overflows(seg->vmaddr, seg->vmsize, &segment_end) || !js_shell_macho_align_up(segment_end, JS_MACHO_PAGE_GRANULE, &segment_high)) {
            js_shell_loader_fail("mach-o segment protection range overflows");
            return 0;
        }
        if (mprotect((unsigned char *)mapping + (segment_low - plan->vm_low), (size_t)(segment_high - segment_low), js_shell_macho_mmap_prot(seg->initprot)) != 0) {
            js_shell_loader_fail("mach-o segment protection failed");
            return 0;
        }
    }
    return 1;
}

static int js_shell_macho_segment_offset_to_vmaddr(const js_macho_image_plan *plan, unsigned int segment_index, uint64_t segment_offset, uint64_t *vmaddr_out) {
    if (segment_index >= plan->segment_count) return 0;
    const js_macho_segment_plan *seg = &plan->segments[segment_index];
    if (segment_offset > seg->vmsize || js_shell_macho_add_overflows(seg->vmaddr, segment_offset, vmaddr_out)) return 0;
    return js_shell_macho_range_inside_mapping(plan, *vmaddr_out, sizeof(uint64_t));
}

static int js_shell_macho_apply_rebase_at(void *mapping, const js_macho_image_plan *plan, uint64_t vmaddr) {
    if (!js_shell_macho_range_inside_mapping(plan, vmaddr, sizeof(uint64_t))) {
        js_shell_loader_fail("mach-o rebase target is outside anonymous mapping");
        return 0;
    }
    uint64_t *slot = (uint64_t *)((unsigned char *)mapping + (vmaddr - plan->vm_low));
    *slot += plan->slide;
    return 1;
}

static int js_shell_macho_apply_rebase_stream(void *mapping, const js_macho_image_plan *plan, const unsigned char *base, size_t size) {
    const unsigned char *p = base;
    const unsigned char *end = base + size;
    uint64_t vmaddr = 0;
    uint64_t ignored = 0;
    unsigned int saw_done = size == 0u;
    while (p < end) {
        unsigned char byte = *p++;
        unsigned char opcode = byte & JS_REBASE_OPCODE_MASK;
        unsigned char imm = byte & JS_REBASE_IMMEDIATE_MASK;
        if (opcode == JS_REBASE_OPCODE_DONE) { saw_done = 1; break; }
        if (opcode == JS_REBASE_OPCODE_SET_TYPE_IMM) {
            (void)imm;
        } else if (opcode == JS_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p || !js_shell_macho_segment_offset_to_vmaddr(plan, imm, ignored, &vmaddr)) return 0;
        } else if (opcode == JS_REBASE_OPCODE_ADD_ADDR_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p || js_shell_macho_add_overflows(vmaddr, ignored, &vmaddr) || !js_shell_macho_range_inside_mapping(plan, vmaddr, sizeof(uint64_t))) return 0;
        } else if (opcode == JS_REBASE_OPCODE_ADD_ADDR_IMM_SCALED) {
            uint64_t addend = (uint64_t)imm * sizeof(uint64_t);
            if (js_shell_macho_add_overflows(vmaddr, addend, &vmaddr) || !js_shell_macho_range_inside_mapping(plan, vmaddr, sizeof(uint64_t))) return 0;
        } else if (opcode == JS_REBASE_OPCODE_DO_REBASE_IMM_TIMES) {
            for (unsigned int i = 0; i < imm; i++) {
                if (!js_shell_macho_apply_rebase_at(mapping, plan, vmaddr) || js_shell_macho_add_overflows(vmaddr, sizeof(uint64_t), &vmaddr)) return 0;
            }
        } else if (opcode == JS_REBASE_OPCODE_DO_REBASE_ULEB_TIMES) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p) return 0;
            for (uint64_t i = 0; i < ignored; i++) {
                if (!js_shell_macho_apply_rebase_at(mapping, plan, vmaddr) || js_shell_macho_add_overflows(vmaddr, sizeof(uint64_t), &vmaddr)) return 0;
            }
        } else if (opcode == JS_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            uint64_t advance = 0;
            if (!p || js_shell_macho_add_overflows(sizeof(uint64_t), ignored, &advance) || !js_shell_macho_apply_rebase_at(mapping, plan, vmaddr) || js_shell_macho_add_overflows(vmaddr, advance, &vmaddr)) return 0;
        } else if (opcode == JS_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB) {
            uint64_t count = 0;
            uint64_t skip = 0;
            uint64_t advance = 0;
            p = js_shell_read_uleb128(p, end, &count);
            if (!p) return 0;
            p = js_shell_read_uleb128(p, end, &skip);
            if (!p) return 0;
            if (js_shell_macho_add_overflows(sizeof(uint64_t), skip, &advance)) return 0;
            for (uint64_t i = 0; i < count; i++) {
                if (!js_shell_macho_apply_rebase_at(mapping, plan, vmaddr)) return 0;
                if (js_shell_macho_add_overflows(vmaddr, advance, &vmaddr)) return 0;
            }
        } else {
            return 0;
        }
    }
    return saw_done && p <= end;
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

static const unsigned char *js_shell_read_sleb128_value(const unsigned char *p, const unsigned char *end, int64_t *out) {
    uint64_t value = 0;
    unsigned int shift = 0;
    unsigned char byte = 0;
    while (p < end && shift < 64u) {
        byte = *p++;
        value |= ((uint64_t)(byte & 0x7fu)) << shift;
        shift += 7u;
        if ((byte & 0x80u) == 0) {
            if (shift < 64u && (byte & 0x40u)) value |= (~0ull) << shift;
            *out = (int64_t)value;
            return p;
        }
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

static int js_shell_macho_resolve_bind_symbol(const char *symbol, int dylib_ordinal, int64_t addend, uint64_t *resolved_out) {
    (void)symbol;
    (void)dylib_ordinal;
    (void)addend;
    (void)resolved_out;
    js_shell_loader_fail("mach-o bind symbol resolver is not available for anonymous mapping");
    return 0;
}

static int js_shell_macho_apply_bind_at(void *mapping, const js_macho_image_plan *plan, uint64_t vmaddr, const char *symbol, int dylib_ordinal, int64_t addend) {
    uint64_t resolved = 0;
    if (!symbol || !symbol[0]) {
        js_shell_loader_fail("mach-o bind opcode reached a slot without a symbol");
        return 0;
    }
    if (!js_shell_macho_range_inside_mapping(plan, vmaddr, sizeof(uint64_t))) {
        js_shell_loader_fail("mach-o bind target is outside anonymous mapping");
        return 0;
    }
    if (!js_shell_macho_resolve_bind_symbol(symbol, dylib_ordinal, addend, &resolved)) return 0;
    uint64_t *slot = (uint64_t *)((unsigned char *)mapping + (vmaddr - plan->vm_low));
    *slot = resolved;
    return 1;
}

static int js_shell_macho_apply_bind_stream(void *mapping, const js_macho_image_plan *plan, const unsigned char *base, size_t size) {
    const unsigned char *p = base;
    const unsigned char *end = base + size;
    uint64_t vmaddr = 0;
    uint64_t ignored = 0;
    int64_t addend = 0;
    int dylib_ordinal = 0;
    const char *symbol = 0;
    unsigned int saw_done = size == 0u;
    while (p < end) {
        unsigned char byte = *p++;
        unsigned char opcode = byte & JS_BIND_OPCODE_MASK;
        unsigned char imm = byte & 0x0fu;
        if (opcode == JS_BIND_OPCODE_DONE) { saw_done = 1; break; }
        if (opcode == JS_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM) {
            dylib_ordinal = imm;
        } else if (opcode == JS_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p || ignored > INT32_MAX) return 0;
            dylib_ordinal = (int)ignored;
        } else if (opcode == JS_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM) {
            dylib_ordinal = imm == 0 ? 0 : (int)(imm | 0xfffffff0u);
        } else if (opcode == JS_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM) {
            symbol = (const char *)p;
            p = js_shell_skip_cstring(p, end);
            if (!p) return 0;
        } else if (opcode == JS_BIND_OPCODE_SET_TYPE_IMM) {
            (void)imm;
        } else if (opcode == JS_BIND_OPCODE_SET_ADDEND_SLEB) {
            p = js_shell_read_sleb128_value(p, end, &addend);
            if (!p) return 0;
        } else if (opcode == JS_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p || !js_shell_macho_segment_offset_to_vmaddr(plan, imm, ignored, &vmaddr)) return 0;
        } else if (opcode == JS_BIND_OPCODE_ADD_ADDR_ULEB) {
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p || js_shell_macho_add_overflows(vmaddr, ignored, &vmaddr) || !js_shell_macho_range_inside_mapping(plan, vmaddr, sizeof(uint64_t))) return 0;
        } else if (opcode == JS_BIND_OPCODE_DO_BIND) {
            if (!js_shell_macho_apply_bind_at(mapping, plan, vmaddr, symbol, dylib_ordinal, addend) || js_shell_macho_add_overflows(vmaddr, sizeof(uint64_t), &vmaddr)) return 0;
        } else if (opcode == JS_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) {
            uint64_t advance = 0;
            p = js_shell_read_uleb128(p, end, &ignored);
            if (!p || js_shell_macho_add_overflows(sizeof(uint64_t), ignored, &advance) || !js_shell_macho_apply_bind_at(mapping, plan, vmaddr, symbol, dylib_ordinal, addend) || js_shell_macho_add_overflows(vmaddr, advance, &vmaddr)) return 0;
        } else if (opcode == JS_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED) {
            uint64_t advance = sizeof(uint64_t) + ((uint64_t)imm * sizeof(uint64_t));
            if (!js_shell_macho_apply_bind_at(mapping, plan, vmaddr, symbol, dylib_ordinal, addend) || js_shell_macho_add_overflows(vmaddr, advance, &vmaddr)) return 0;
        } else if (opcode == JS_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB) {
            uint64_t count = 0;
            uint64_t skip = 0;
            uint64_t advance = 0;
            p = js_shell_read_uleb128(p, end, &count);
            if (!p) return 0;
            p = js_shell_read_uleb128(p, end, &skip);
            if (!p || js_shell_macho_add_overflows(sizeof(uint64_t), skip, &advance)) return 0;
            for (uint64_t i = 0; i < count; i++) {
                if (!js_shell_macho_apply_bind_at(mapping, plan, vmaddr, symbol, dylib_ordinal, addend)) return 0;
                if (js_shell_macho_add_overflows(vmaddr, advance, &vmaddr)) return 0;
            }
        } else {
            return 0;
        }
    }
    return saw_done && p <= end;
}

static int js_shell_macho_resolve_export_rva(const unsigned char *base, size_t size, const char *needle, uint64_t *rva_out) {
    const unsigned char *end = base + size;
    typedef struct js_export_trie_node_state { const unsigned char *node; char prefix[128]; } js_export_trie_node_state;
    js_export_trie_node_state stack[96];
    size_t stack_count = 0;
    stack[stack_count].node = base;
    stack[stack_count].prefix[0] = 0;
    stack_count++;
    while (stack_count) {
        js_export_trie_node_state state = stack[--stack_count];
        const unsigned char *node = state.node;
        if (node < base || node >= end) return 0;
        uint64_t terminal_size = 0;
        const unsigned char *p = js_shell_read_uleb128(node, end, &terminal_size);
        if (!p || terminal_size > (uint64_t)(end - p)) return 0;
        if (terminal_size) {
            const unsigned char *terminal_end = p + terminal_size;
            uint64_t flags = 0;
            uint64_t address = 0;
            const unsigned char *tp = js_shell_read_uleb128(p, terminal_end, &flags);
            if (!tp) return 0;
            tp = js_shell_read_uleb128(tp, terminal_end, &address);
            if (!tp) return 0;
            if (strcmp(state.prefix, needle) == 0) {
                *rva_out = address;
                return 1;
            }
        }
        p += terminal_size;
        if (p >= end) return 0;
        unsigned int child_count = *p++;
        for (unsigned int i = 0; i < child_count; i++) {
            const char *edge = (const char *)p;
            size_t edge_len = strnlen(edge, (size_t)(end - p));
            if (p + edge_len >= end) return 0;
            p += edge_len + 1u;
            uint64_t child_offset = 0;
            p = js_shell_read_uleb128(p, end, &child_offset);
            if (!p || child_offset >= size) return 0;
            if (stack_count < sizeof(stack) / sizeof(stack[0])) {
                size_t prefix_len = strnlen(state.prefix, sizeof(state.prefix));
                if (prefix_len + edge_len >= sizeof(stack[stack_count].prefix)) return 0;
                memcpy(stack[stack_count].prefix, state.prefix, prefix_len);
                memcpy(stack[stack_count].prefix + prefix_len, edge, edge_len);
                stack[stack_count].prefix[prefix_len + edge_len] = 0;
                stack[stack_count].node = base + child_offset;
                stack_count++;
            }
        }
    }
    return 0;
}

static int js_shell_export_trie_has_symbol(const unsigned char *base, size_t size, const char *needle) {
    uint64_t ignored = 0;
    return js_shell_macho_resolve_export_rva(base, size, needle, &ignored);
}

static int js_shell_macho_resolve_export_pointer(void *mapping, const js_macho_image_plan *plan, const unsigned char *export_base, size_t export_size, const char *symbol, int require_executable, void **ptr_out) {
    uint64_t rva = 0;
    uint64_t vmaddr = 0;
    if (!js_shell_macho_resolve_export_rva(export_base, export_size, symbol, &rva)) {
        js_shell_loader_fail("mach-o export symbol address is missing");
        return 0;
    }
    if (js_shell_macho_add_overflows(plan->vm_low, rva, &vmaddr) || !js_shell_macho_range_inside_mapping(plan, vmaddr, 1u)) {
        js_shell_loader_fail("mach-o export symbol address is outside anonymous mapping");
        return 0;
    }
    if (require_executable && (vmaddr < plan->text_low || vmaddr >= plan->text_high)) {
        js_shell_loader_fail("mach-o export entrypoint is outside executable image pages");
        return 0;
    }
    *ptr_out = (unsigned char *)mapping + (vmaddr - plan->vm_low);
    return 1;
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
    const js_dyld_info_command *dyld = 0;
    const js_symtab_command *symtab = 0;
    js_macho_image_plan image_plan;
    js_shell_macho_init_image_plan(&image_plan);
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
            if (!js_shell_macho_plan_segment(&image_plan, seg, size)) {
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
                if ((section->flags & JS_SECTION_TYPE) == JS_S_MOD_INIT_FUNC_POINTERS && !js_shell_macho_plan_initializer_section(&image_plan, section)) return 0;
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
    if (!js_shell_macho_finalize_image_plan(&image_plan)) {
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
    if (!dyld->export_size || !js_shell_export_trie_has_symbol(bytes + dyld->export_off, dyld->export_size, "_JNI_OnLoad")) {
        js_shell_loader_fail("mach-o payload does not export _JNI_OnLoad");
        return 0;
    }
    if (!js_shell_export_trie_has_symbol(bytes + dyld->export_off, dyld->export_size, "_js_native_abi_table_v1")) {
        js_shell_loader_fail("mach-o payload does not export native ABI table");
        return 0;
    }

    void *planned_mapping = 0;
    if (!js_shell_macho_materialize_segments(bytes, &image_plan, &planned_mapping)) {
        return 0;
    }
    image_plan.slide = (uint64_t)(uintptr_t)planned_mapping - image_plan.vm_low;
    if (!js_shell_macho_apply_rebase_stream(planned_mapping, &image_plan, bytes + dyld->rebase_off, dyld->rebase_size)) {
        munmap(planned_mapping, (size_t)image_plan.mapping_size);
        js_shell_loader_fail("mach-o rebase application failed inside anonymous mapping");
        return 0;
    }
    if (!js_shell_macho_apply_bind_stream(planned_mapping, &image_plan, bytes + dyld->bind_off, dyld->bind_size) ||
        !js_shell_macho_apply_bind_stream(planned_mapping, &image_plan, bytes + dyld->lazy_bind_off, dyld->lazy_bind_size)) {
        munmap(planned_mapping, (size_t)image_plan.mapping_size);
        if (!g_js_shell_loader_failure || strcmp(g_js_shell_loader_failure, "mach-o loader has not started") == 0) {
            js_shell_loader_fail("mach-o bind application failed inside anonymous mapping");
        }
        return 0;
    }
    if (!js_shell_macho_validate_initializers(planned_mapping, &image_plan)) {
        munmap(planned_mapping, (size_t)image_plan.mapping_size);
        return 0;
    }
    if (!js_shell_macho_protect_segments(planned_mapping, &image_plan)) {
        munmap(planned_mapping, (size_t)image_plan.mapping_size);
        return 0;
    }
    void *resolved_jni_on_load = 0;
    void *resolved_native_abi_table = 0;
    if (!js_shell_macho_resolve_export_pointer(planned_mapping, &image_plan, bytes + dyld->export_off, dyld->export_size, "_JNI_OnLoad", 1, &resolved_jni_on_load) ||
        !js_shell_macho_resolve_export_pointer(planned_mapping, &image_plan, bytes + dyld->export_off, dyld->export_size, "_js_native_abi_table_v1", 0, &resolved_native_abi_table)) {
        munmap(planned_mapping, (size_t)image_plan.mapping_size);
        return 0;
    }
    (void)resolved_jni_on_load;
    (void)resolved_native_abi_table;
    munmap(planned_mapping, (size_t)image_plan.mapping_size);

    if (g_js_shell_macho_fail_closed_marker[0] != 'J') return 0;
    js_shell_loader_fail("mach-o payload validated through segments, sections, anonymous image layout, segment materialization, rebase and bind/lazy-bind application, export address resolution, and initializer metadata, but anonymous execution mapping stays fail-closed until runtime execution is verified on macOS");
    return 0;
}

void js_shell_unload_inner_image(js_shell_loaded_image *image) { (void)image; }
const char *js_shell_loader_failure_reason(void) { return g_js_shell_loader_failure; }

#endif
