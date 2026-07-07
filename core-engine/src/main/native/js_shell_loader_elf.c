#include "js_shell_loader.h"

#if defined(__linux__) || defined(__ANDROID__)

#include <dlfcn.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const char *g_js_shell_loader_failure = "elf64 loader has not started";
static char g_js_shell_loader_failure_buffer[192];

typedef struct js_shell_elf_dyn {
    uintptr_t mapped_low;
    uintptr_t mapped_high;
    const Elf64_Sym *symtab;
    const char *strtab;
    const Elf64_Rela *rela_dyn;
    size_t rela_dyn_count;
    const Elf64_Rela *rela_plt;
    size_t rela_plt_count;
    uintptr_t init_array;
    size_t init_array_count;
    uintptr_t init_func;
    uintptr_t fini_array;
    size_t fini_array_count;
    uintptr_t hash;
    uintptr_t gnu_hash;
    uintptr_t strsz;
} js_shell_elf_dyn;

static void js_shell_loader_fail(const char *reason) {
    g_js_shell_loader_failure = reason;
}

static void js_shell_loader_fail_symbol(const char *prefix, const char *symbol) {
    if (!prefix) prefix = "elf64 relocation symbol failure";
    if (!symbol) symbol = "<null>";
    snprintf(g_js_shell_loader_failure_buffer, sizeof(g_js_shell_loader_failure_buffer), "%s: %.120s", prefix, symbol);
    g_js_shell_loader_failure = g_js_shell_loader_failure_buffer;
}

static uintptr_t js_shell_align_down(uintptr_t value, uintptr_t align) {
    return value & ~(align - 1u);
}

static uintptr_t js_shell_align_up(uintptr_t value, uintptr_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

static int js_shell_page_prot(uint32_t flags) {
    int prot = 0;
    if (flags & PF_R) prot |= PROT_READ;
    if (flags & PF_W) prot |= PROT_WRITE;
    if (flags & PF_X) prot |= PROT_EXEC;
    return prot ? prot : PROT_NONE;
}

static int js_shell_validate_range(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

static int js_shell_mapped_range_contains(uintptr_t low, uintptr_t high, uintptr_t addr, size_t size) {
    return high >= low && addr >= low && addr <= high && size <= high - addr;
}

static int js_shell_dyn_range_contains(const js_shell_elf_dyn *dyn, uintptr_t addr, size_t size) {
    return dyn && js_shell_mapped_range_contains(dyn->mapped_low, dyn->mapped_high, addr, size);
}

static int js_shell_pointer_in_range(uintptr_t low, uintptr_t high, const void *ptr) {
    return ptr && js_shell_mapped_range_contains(low, high, (uintptr_t)ptr, 1u);
}

static void *js_shell_host_symbol(const char *name) {
    if (!name || !name[0]) return 0;
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (symbol) return symbol;
    void *self = dlopen(0, RTLD_NOW | RTLD_LOCAL);
    if (!self) return 0;
    symbol = dlsym(self, name);
    dlclose(self);
    return symbol;
}

static int js_shell_sysv_symbol_count(uintptr_t image, const js_shell_elf_dyn *dyn, size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!dyn->hash) return 1;
    const uint32_t *hash = (const uint32_t *)(image + dyn->hash);
    if (!js_shell_dyn_range_contains(dyn, (uintptr_t)hash, 2u * sizeof(uint32_t))) {
        js_shell_loader_fail("elf64 SYSV hash header is outside the mapped image");
        return 0;
    }
    if (out_count) *out_count = (size_t)hash[1];
    return 1;
}

static int js_shell_gnu_hash_symbol_count(uintptr_t image, const js_shell_elf_dyn *dyn, size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!dyn->gnu_hash || !dyn->symtab) return 1;
    const uint32_t *base = (const uint32_t *)(image + dyn->gnu_hash);
    if (!js_shell_dyn_range_contains(dyn, (uintptr_t)base, 4u * sizeof(uint32_t))) {
        js_shell_loader_fail("elf64 GNU hash header is outside the mapped image");
        return 0;
    }
    uint32_t nbuckets = base[0];
    uint32_t symoffset = base[1];
    uint32_t bloom_size = base[2];
    const uint32_t *buckets = (const uint32_t *)((const uintptr_t *)(base + 4) + bloom_size);
    const uint32_t *chains = buckets + nbuckets;
    if (!js_shell_dyn_range_contains(dyn, (uintptr_t)(base + 4), (size_t)bloom_size * sizeof(uintptr_t)) ||
        !js_shell_dyn_range_contains(dyn, (uintptr_t)buckets, (size_t)nbuckets * sizeof(uint32_t))) {
        js_shell_loader_fail("elf64 GNU hash bloom or bucket table is outside the mapped image");
        return 0;
    }
    size_t max_sym = (size_t)symoffset;
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t bucket = buckets[i];
        if (bucket < symoffset) continue;
        size_t sym = (size_t)bucket;
        const uint32_t *chain = chains + (sym - symoffset);
        if (!js_shell_dyn_range_contains(dyn, (uintptr_t)chain, sizeof(*chain))) {
            js_shell_loader_fail("elf64 GNU hash chain is outside the mapped image");
            return 0;
        }
        while (((*chain) & 1u) == 0u) {
            sym++;
            chain++;
            if (!js_shell_dyn_range_contains(dyn, (uintptr_t)chain, sizeof(*chain))) {
                js_shell_loader_fail("elf64 GNU hash chain is outside the mapped image");
                return 0;
            }
        }
        if (sym + 1u > max_sym) max_sym = sym + 1u;
    }
    if (out_count) *out_count = max_sym;
    return 1;
}

static int js_shell_symbol_count(uintptr_t image, const js_shell_elf_dyn *dyn, size_t *out_count) {
    size_t count = 0;
    if (!js_shell_sysv_symbol_count(image, dyn, &count)) return 0;
    if (count) {
        if (out_count) *out_count = count;
        return 1;
    }
    return js_shell_gnu_hash_symbol_count(image, dyn, out_count);
}

static void *js_shell_find_export(uintptr_t image, const js_shell_elf_dyn *dyn, const char *name) {
    if (!dyn->symtab || !dyn->strtab || !name) return 0;
    size_t count = 0;
    if (!js_shell_symbol_count(image, dyn, &count)) return 0;
    if (!count || !js_shell_dyn_range_contains(dyn, (uintptr_t)dyn->symtab, count * sizeof(Elf64_Sym))) return 0;
    for (size_t i = 0; i < count; i++) {
        const Elf64_Sym *sym = dyn->symtab + i;
        if (!js_shell_dyn_range_contains(dyn, (uintptr_t)sym, sizeof(*sym))) continue;
        if (sym->st_name >= dyn->strsz) continue;
        if (sym->st_shndx == SHN_UNDEF || sym->st_value == 0) continue;
        if (strcmp(dyn->strtab + sym->st_name, name) == 0) return (void *)(image + sym->st_value);
    }
    return 0;
}

static int js_shell_apply_rela(uintptr_t image, const js_shell_elf_dyn *dyn, const Elf64_Rela *rela, size_t count) {
    if (!rela || !count) return 1;
    if (!js_shell_dyn_range_contains(dyn, (uintptr_t)rela, count * sizeof(Elf64_Rela))) {
        js_shell_loader_fail("elf64 relocation table is outside the mapped image");
        return 0;
    }
    size_t symbol_count = 0;
    if (!js_shell_symbol_count(image, dyn, &symbol_count)) return 0;
    for (size_t i = 0; i < count; i++) {
        uintptr_t where_addr = image + rela[i].r_offset;
        if (!js_shell_dyn_range_contains(dyn, where_addr, sizeof(uintptr_t))) {
            js_shell_loader_fail("elf64 relocation target is outside the mapped image");
            return 0;
        }
        uintptr_t *where = (uintptr_t *)where_addr;
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        uint32_t sym_index = ELF64_R_SYM(rela[i].r_info);
        uintptr_t value = 0;
        if (sym_index != 0) {
            if (!dyn->symtab || !dyn->strtab) {
                js_shell_loader_fail("elf64 relocation references missing symbol tables");
                return 0;
            }
            if (!symbol_count || sym_index >= symbol_count) {
                js_shell_loader_fail("elf64 relocation symbol index is out of range");
                return 0;
            }
            const Elf64_Sym *sym = dyn->symtab + sym_index;
            if (!js_shell_dyn_range_contains(dyn, (uintptr_t)sym, sizeof(*sym))) {
                js_shell_loader_fail("elf64 relocation symbol entry is out of range");
                return 0;
            }
            if (sym->st_name >= dyn->strsz) {
                js_shell_loader_fail("elf64 relocation symbol name is out of range");
                return 0;
            }
            if (sym->st_shndx != SHN_UNDEF && sym->st_value != 0) {
                value = image + sym->st_value;
            } else {
                void *host = js_shell_host_symbol(dyn->strtab + sym->st_name);
                if (!host) {
                    if (ELF64_ST_BIND(sym->st_info) == STB_WEAK) {
                        value = 0;
                    } else {
                    js_shell_loader_fail_symbol("elf64 relocation could not resolve host symbol", dyn->strtab + sym->st_name);
                    return 0;
                    }
                } else {
                    value = (uintptr_t)host;
                }
            }
        }
        switch (type) {
            case R_X86_64_RELATIVE:
                *where = image + (uintptr_t)rela[i].r_addend;
                break;
            case R_X86_64_64:
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
                *where = value + (uintptr_t)rela[i].r_addend;
                break;
            case R_X86_64_DTPMOD64:
                *where = 1u;
                break;
            case R_X86_64_DTPOFF64:
            case R_X86_64_TPOFF64:
                js_shell_loader_fail("elf64 TLS relocation is not supported by the max shell loader");
                return 0;
            default:
                js_shell_loader_fail("elf64 relocation type is not supported by the max shell loader");
                return 0;
        }
    }
    return 1;
}

static int js_shell_parse_dynamic(uintptr_t image, uintptr_t mapped_low, uintptr_t mapped_high, const Elf64_Dyn *dynamic, size_t dynamic_size, js_shell_elf_dyn *out) {
    memset(out, 0, sizeof(*out));
    out->mapped_low = mapped_low;
    out->mapped_high = mapped_high;
    if (!js_shell_mapped_range_contains(mapped_low, mapped_high, (uintptr_t)dynamic, dynamic_size)) {
        js_shell_loader_fail("elf64 dynamic section is outside the mapped image");
        return 0;
    }
    size_t dyn_count = dynamic_size / sizeof(Elf64_Dyn);
    size_t rela_dyn_size = 0;
    size_t rela_plt_size = 0;
    size_t init_array_size = 0;
    size_t fini_array_size = 0;
    int saw_dt_null = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        switch (dynamic[i].d_tag) {
            case DT_NULL:
                saw_dt_null = 1;
                i = dyn_count;
                break;
            case DT_SYMTAB:
                out->symtab = (const Elf64_Sym *)(image + (uintptr_t)dynamic[i].d_un.d_ptr);
                break;
            case DT_STRTAB:
                out->strtab = (const char *)(image + (uintptr_t)dynamic[i].d_un.d_ptr);
                break;
            case DT_STRSZ:
                out->strsz = (uintptr_t)dynamic[i].d_un.d_val;
                break;
            case DT_RELA:
                out->rela_dyn = (const Elf64_Rela *)(image + (uintptr_t)dynamic[i].d_un.d_ptr);
                break;
            case DT_RELASZ:
                rela_dyn_size = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_JMPREL:
                out->rela_plt = (const Elf64_Rela *)(image + (uintptr_t)dynamic[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                rela_plt_size = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_PLTREL:
                if (dynamic[i].d_un.d_val != DT_RELA) {
                    js_shell_loader_fail("elf64 REL PLT relocations are not supported");
                    return 0;
                }
                break;
            case DT_INIT_ARRAY:
                out->init_array = (uintptr_t)dynamic[i].d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                init_array_size = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_INIT:
                out->init_func = (uintptr_t)dynamic[i].d_un.d_ptr;
                break;
            case DT_FINI_ARRAY:
                out->fini_array = (uintptr_t)dynamic[i].d_un.d_ptr;
                break;
            case DT_FINI_ARRAYSZ:
                fini_array_size = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_HASH:
                out->hash = (uintptr_t)dynamic[i].d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                out->gnu_hash = (uintptr_t)dynamic[i].d_un.d_ptr;
                break;
            case DT_TEXTREL:
                js_shell_loader_fail("elf64 text relocations are not supported");
                return 0;
            default:
                break;
        }
    }
    if (!saw_dt_null) {
        js_shell_loader_fail("elf64 dynamic section is missing DT_NULL terminator");
        return 0;
    }
    out->rela_dyn_count = rela_dyn_size / sizeof(Elf64_Rela);
    out->rela_plt_count = rela_plt_size / sizeof(Elf64_Rela);
    out->init_array_count = init_array_size / sizeof(uintptr_t);
    out->fini_array_count = fini_array_size / sizeof(uintptr_t);
    if (!out->symtab || !out->strtab || !out->strsz) return 0;
    if (!js_shell_mapped_range_contains(mapped_low, mapped_high, (uintptr_t)out->strtab, (size_t)out->strsz)) {
        js_shell_loader_fail("elf64 string table is outside the mapped image");
        return 0;
    }
    if (out->rela_dyn_count && !js_shell_mapped_range_contains(mapped_low, mapped_high, (uintptr_t)out->rela_dyn, out->rela_dyn_count * sizeof(Elf64_Rela))) {
        js_shell_loader_fail("elf64 RELA dynamic table is outside the mapped image");
        return 0;
    }
    if (out->rela_plt_count && !js_shell_mapped_range_contains(mapped_low, mapped_high, (uintptr_t)out->rela_plt, out->rela_plt_count * sizeof(Elf64_Rela))) {
        js_shell_loader_fail("elf64 RELA PLT table is outside the mapped image");
        return 0;
    }
    if (out->init_array_count && !js_shell_mapped_range_contains(mapped_low, mapped_high, image + out->init_array, out->init_array_count * sizeof(uintptr_t))) {
        js_shell_loader_fail("elf64 init array is outside the mapped image");
        return 0;
    }
    if (out->fini_array_count && !js_shell_mapped_range_contains(mapped_low, mapped_high, image + out->fini_array, out->fini_array_count * sizeof(uintptr_t))) {
        js_shell_loader_fail("elf64 fini array is outside the mapped image");
        return 0;
    }
    return 1;
}

int js_shell_load_inner_image(const js_shell_payload_view *payload, js_shell_loaded_image *out_image) {
    if (!payload || !out_image || !payload->decoded_payload || payload->decoded_payload_size < sizeof(Elf64_Ehdr)) {
        js_shell_loader_fail("elf64 payload is empty or missing decoded bytes");
        return 0;
    }
    memset(out_image, 0, sizeof(*out_image));
    const unsigned char *bytes = payload->decoded_payload;
    size_t size = payload->decoded_payload_size;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)bytes;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB) {
        js_shell_loader_fail("elf64 payload header is not a little-endian ELF64 image");
        return 0;
    }
    if (eh->e_type != ET_DYN || eh->e_machine != EM_X86_64 || eh->e_phentsize != sizeof(Elf64_Phdr)) {
        js_shell_loader_fail("elf64 payload is not a supported x86_64 ET_DYN image");
        return 0;
    }
    if (!js_shell_validate_range(eh->e_phoff, (size_t)eh->e_phnum * sizeof(Elf64_Phdr), size)) {
        js_shell_loader_fail("elf64 program header table is out of range");
        return 0;
    }

    const Elf64_Phdr *ph = (const Elf64_Phdr *)(bytes + eh->e_phoff);
    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    uintptr_t exec_low_vaddr = UINTPTR_MAX;
    uintptr_t exec_high_vaddr = 0;
    const Elf64_Phdr *dynamic_ph = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            if (!js_shell_validate_range((size_t)ph[i].p_offset, (size_t)ph[i].p_filesz, size) || ph[i].p_memsz < ph[i].p_filesz) {
                js_shell_loader_fail("elf64 load segment is out of range");
                return 0;
            }
            uintptr_t start = js_shell_align_down((uintptr_t)ph[i].p_vaddr, 0x1000u);
            uintptr_t end = js_shell_align_up((uintptr_t)ph[i].p_vaddr + (uintptr_t)ph[i].p_memsz, 0x1000u);
            if (start < min_vaddr) min_vaddr = start;
            if (end > max_vaddr) max_vaddr = end;
            if (ph[i].p_flags & PF_X) {
                if (start < exec_low_vaddr) exec_low_vaddr = start;
                if (end > exec_high_vaddr) exec_high_vaddr = end;
            }
        } else if (ph[i].p_type == PT_DYNAMIC) {
            dynamic_ph = ph + i;
        }
    }
    if (min_vaddr == UINTPTR_MAX || max_vaddr <= min_vaddr || !dynamic_ph) {
        js_shell_loader_fail("elf64 payload has no PT_LOAD or PT_DYNAMIC segments");
        return 0;
    }
    if (exec_low_vaddr == UINTPTR_MAX || exec_high_vaddr <= exec_low_vaddr) {
        js_shell_loader_fail("elf64 payload has no executable PT_LOAD segment");
        return 0;
    }

    long page_size_long = sysconf(_SC_PAGESIZE);
    uintptr_t page_size = page_size_long > 0 ? (uintptr_t)page_size_long : 4096u;
    min_vaddr = js_shell_align_down(min_vaddr, page_size);
    max_vaddr = js_shell_align_up(max_vaddr, page_size);
    size_t image_size = (size_t)(max_vaddr - min_vaddr);
    uintptr_t exec_low = 0;
    uintptr_t exec_high = 0;
    void *mapping = mmap(0, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        js_shell_loader_fail("elf64 anonymous mmap failed");
        return 0;
    }
    uintptr_t image = (uintptr_t)mapping - min_vaddr;
    exec_low = image + exec_low_vaddr;
    exec_high = image + exec_high_vaddr;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        memcpy((void *)(image + (uintptr_t)ph[i].p_vaddr), bytes + ph[i].p_offset, (size_t)ph[i].p_filesz);
    }

    const Elf64_Dyn *dynamic = (const Elf64_Dyn *)(image + (uintptr_t)dynamic_ph->p_vaddr);
    js_shell_elf_dyn dyn;
    uintptr_t mapped_low = (uintptr_t)mapping;
    uintptr_t mapped_high = mapped_low + image_size;
    if (!js_shell_parse_dynamic(image, mapped_low, mapped_high, dynamic, (size_t)dynamic_ph->p_memsz, &dyn)) {
        munmap(mapping, image_size);
        return 0;
    }
    if (!js_shell_apply_rela(image, &dyn, dyn.rela_dyn, dyn.rela_dyn_count) || !js_shell_apply_rela(image, &dyn, dyn.rela_plt, dyn.rela_plt_count)) {
        munmap(mapping, image_size);
        return 0;
    }

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        uintptr_t start = js_shell_align_down(image + (uintptr_t)ph[i].p_vaddr, page_size);
        uintptr_t end = js_shell_align_up(image + (uintptr_t)ph[i].p_vaddr + (uintptr_t)ph[i].p_memsz, page_size);
        if (mprotect((void *)start, (size_t)(end - start), js_shell_page_prot(ph[i].p_flags)) != 0) {
            munmap(mapping, image_size);
            js_shell_loader_fail("elf64 segment mprotect failed");
            return 0;
        }
    }

    if (dyn.init_func) {
        uintptr_t init_addr = image + dyn.init_func;
        if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)init_addr)) {
            munmap(mapping, image_size);
            js_shell_loader_fail("elf64 init function is outside executable image pages");
            return 0;
        }
        void (*init_func)(void) = (void (*)(void))init_addr;
        init_func();
    }

    if (dyn.init_array && dyn.init_array_count) {
        void (**init_array)(void) = (void (**)(void))(image + dyn.init_array);
        for (size_t i = 0; i < dyn.init_array_count; i++) {
            if (!init_array[i]) continue;
            if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)init_array[i])) {
                munmap(mapping, image_size);
                js_shell_loader_fail("elf64 init array function is outside executable image pages");
                return 0;
            }
            init_array[i]();
        }
    }

    out_image->jni_on_load = (jint (*)(JavaVM *, void *))js_shell_find_export(image, &dyn, "JNI_OnLoad");
    out_image->jni_on_unload = (void (*)(JavaVM *, void *))js_shell_find_export(image, &dyn, "JNI_OnUnload");
    out_image->native_abi_table_v1 = (const js_native_abi_table *(*)(void))js_shell_find_export(image, &dyn, "js_native_abi_table_v1");
    if (!out_image->jni_on_load) {
        munmap(mapping, image_size);
        js_shell_loader_fail("elf64 payload does not export JNI_OnLoad");
        return 0;
    }
    if (!out_image->native_abi_table_v1) {
        munmap(mapping, image_size);
        js_shell_loader_fail("elf64 payload does not export native ABI table");
        return 0;
    }
    if (!js_shell_pointer_in_range(exec_low, exec_high, (const void *)out_image->jni_on_load) ||
        !js_shell_pointer_in_range(exec_low, exec_high, (const void *)out_image->native_abi_table_v1) ||
        (out_image->jni_on_unload && !js_shell_pointer_in_range(exec_low, exec_high, (const void *)out_image->jni_on_unload))) {
        munmap(mapping, image_size);
        js_shell_loader_fail("elf64 exported JNI or ABI entry is outside executable image pages");
        return 0;
    }
    out_image->image_base = mapping;
    out_image->image_size = image_size;
    out_image->code_low = (void *)exec_low;
    out_image->code_size = (size_t)(exec_high - exec_low);
    g_js_shell_loader_failure = "elf64 anonymous memory loader completed";
    return 1;
}

void js_shell_unload_inner_image(js_shell_loaded_image *image) {
    if (!image || !image->image_base || !image->image_size) return;
    munmap(image->image_base, image->image_size);
    memset(image, 0, sizeof(*image));
}

const char *js_shell_loader_failure_reason(void) { return g_js_shell_loader_failure; }

#endif
