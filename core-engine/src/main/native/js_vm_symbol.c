#include "js_vm_symbol.h"
#include "js_crypto.h"
#include "js_vm_core.h"
#include "js_vm_resource.h"

#include <stdlib.h>
#include <string.h>

JS_HIDDEN unsigned long long js_vm_hash64_string(const char *value) {
    if (!value) return 0ULL;
    unsigned long long hash = 0xcbf29ce484222325ULL;
    for (const unsigned char *p = (const unsigned char*)value; *p; ++p) {
        hash ^= (unsigned long long)(*p);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

JS_HIDDEN js_vm_symbol_cache_entry* js_vm_symbol_cache_lookup(js_vm_program *p, int cp_idx, int kind) {
    if (!p || !p->symbols || p->symbol_count <= 0) return NULL;
    for (int i = 0; i < p->symbol_count; i++) {
        if (p->symbols[i].cp_idx == cp_idx && p->symbols[i].kind == kind) return &p->symbols[i];
    }
    return NULL;
}

JS_HIDDEN void js_vm_symbol_cache_clear_entry(JNIEnv *env, js_vm_symbol_cache_entry *entry) {
    if (!entry) return;
    if (env && entry->cls) (*env)->DeleteGlobalRef(env, entry->cls);
    if (entry->arg_tags) { js_vbc4_wipe_volatile(entry->arg_tags, (size_t)entry->argc); free(entry->arg_tags); }
    if (entry->type_name) { js_vbc4_wipe_volatile(entry->type_name, strlen(entry->type_name)); free(entry->type_name); }
    memset(entry, 0, sizeof(*entry));
}

JS_HIDDEN js_vm_symbol_cache_entry* js_vm_class_cache_add(JNIEnv *env, js_vm_program *p, int cp_idx, int kind, jclass cls, const char *type_name) {
    if (!env || !p || !cls || !type_name || !*type_name) return NULL;
    js_vm_symbol_cache_entry *existing = js_vm_symbol_cache_lookup(p, cp_idx, kind);
    if (existing) return existing;
    js_vm_symbol_cache_entry *grown = (js_vm_symbol_cache_entry*)realloc(p->symbols, (size_t)(p->symbol_count + 1) * sizeof(js_vm_symbol_cache_entry));
    if (!grown) return NULL;
    p->symbols = grown;
    js_vm_symbol_cache_entry *slot = &p->symbols[p->symbol_count];
    memset(slot, 0, sizeof(*slot));
    slot->cp_idx = cp_idx;
    slot->kind = kind;
    slot->cls = (jclass)(*env)->NewGlobalRef(env, cls);
    if ((*env)->ExceptionCheck(env) || !slot->cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        memset(slot, 0, sizeof(*slot));
        return NULL;
    }
    slot->type_name = js_strdup(type_name);
    if (!slot->type_name) {
        js_vm_symbol_cache_clear_entry(env, slot);
        return NULL;
    }
    p->symbol_count++;
    return slot;
}

JS_HIDDEN js_vm_symbol_cache_entry* js_vm_symbol_cache_add(JNIEnv *env, js_vm_program *p, int cp_idx, int kind, jclass cls, jmethodID mid, jfieldID fid, unsigned char tag, const js_vm_method_ref *ref, const char *lookup_name, unsigned char ret_tag, unsigned char is_constructor) {
    if (!env || !p || !cls || !ref || !ref->owner || !ref->name || !ref->desc) return NULL;
    js_vm_symbol_cache_entry *existing = js_vm_symbol_cache_lookup(p, cp_idx, kind);
    if (existing) return existing;
    js_vm_symbol_cache_entry *grown = (js_vm_symbol_cache_entry*)realloc(p->symbols, (size_t)(p->symbol_count + 1) * sizeof(js_vm_symbol_cache_entry));
    if (!grown) return NULL;
    p->symbols = grown;
    js_vm_symbol_cache_entry *slot = &p->symbols[p->symbol_count];
    memset(slot, 0, sizeof(*slot));
    slot->cp_idx = cp_idx;
    slot->kind = kind;
    slot->cls = (jclass)(*env)->NewGlobalRef(env, cls);
    if ((*env)->ExceptionCheck(env) || !slot->cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        memset(slot, 0, sizeof(*slot));
        return NULL;
    }
    slot->mid = mid;
    slot->fid = fid;
    slot->tag = tag;
    slot->class_hash = js_vm_hash64_string(ref->owner);
    slot->meth_hash = js_vm_hash64_string(ref->name);
    slot->sig_hash = js_vm_hash64_string(ref->desc);
    slot->ret_tag = ret_tag;
    slot->is_constructor = is_constructor;
    slot->is_array_clone = (unsigned char)(kind == 5 && strcmp(ref->name, "clone") == 0 && strcmp(ref->desc, "()Ljava/lang/Object;") == 0);
    slot->is_class_resource_stream = (unsigned char)(kind == 5 && strcmp(ref->owner, "java/lang/Class") == 0 && strcmp(ref->name, "getResourceAsStream") == 0 && strcmp(ref->desc, "(Ljava/lang/String;)Ljava/io/InputStream;") == 0);
    slot->is_class_mirror = (unsigned char)(kind == 5 && strcmp(ref->owner, "java/lang/Class") == 0 &&
        !((strcmp(ref->name, "getDeclaredMethods") == 0 && strcmp(ref->desc, "()[Ljava/lang/reflect/Method;") == 0) ||
          (strcmp(ref->name, "getMethods") == 0 && strcmp(ref->desc, "()[Ljava/lang/reflect/Method;") == 0) ||
          (strcmp(ref->name, "getDeclaredFields") == 0 && strcmp(ref->desc, "()[Ljava/lang/reflect/Field;") == 0) ||
          (strcmp(ref->name, "getFields") == 0 && strcmp(ref->desc, "()[Ljava/lang/reflect/Field;") == 0)));
    slot->is_class_loader_define_class = (unsigned char)(kind == 5 && strcmp(ref->name, "defineClass") == 0 && strcmp(ref->desc, "(Ljava/lang/String;[BII)Ljava/lang/Class;") == 0);
    slot->is_class_loader_load_class = (unsigned char)(kind == 5 && strcmp(ref->name, "loadClass") == 0 && strcmp(ref->desc, "(Ljava/lang/String;)Ljava/lang/Class;") == 0);
    if ((kind == 4 || kind == 5) && p->original_owner && p->original_name && p->original_desc && strcmp(ref->owner, p->original_owner) == 0 && strcmp(ref->desc, p->original_desc) == 0) {
        int self = strcmp(ref->name, p->original_name) == 0 || (lookup_name && strcmp(lookup_name, p->original_name) == 0);
        if (!self && lookup_name) {
            char *current_mapped = js_lookup_bound_method(env, p->original_owner, p->original_name, p->original_desc);
            self = current_mapped && current_mapped[0] && strcmp(lookup_name, current_mapped) == 0;
            free(current_mapped);
        }
        slot->is_self_call = (unsigned char)self;
    } else {
        slot->is_self_call = 0;
    }
    if (kind == 4 || kind == 5) {
        char *tags = NULL;
        int parsed_argc = 0;
        if (!js_vm_descriptor_arg_tags(ref->desc, &tags, &parsed_argc)) {
            js_vm_symbol_cache_clear_entry(env, slot);
            return NULL;
        }
        slot->arg_tags = tags;
        slot->argc = parsed_argc;
    }
    p->symbol_count++;
    return slot;
}

JS_HIDDEN int js_vm_resolve_field_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind) {
    if (!env || !p || cp_idx < 0) return 0;
    if (js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind)) return 1;
    char *ref = js_vm_cp_string_owned(p, cp_idx);
    if (!ref) return 0;
    js_vm_method_ref fr;
    if (!js_vm_parse_method_ref(ref, &fr)) {
        js_vbc4_wipe_volatile(ref, strlen(ref));
        free(ref);
        return 0;
    }
    js_vbc4_wipe_volatile(ref, strlen(ref));
    free(ref);
    char tag = 'L';
    if (fr.desc && fr.desc[0]) {
        tag = fr.desc[0] == '[' ? '[' : fr.desc[0];
    }
    jclass cls = js_vm_find_class_name(env, fr.owner);
    if ((*env)->ExceptionCheck(env) || !cls) { js_vm_free_method_ref(&fr); return 0; }
    jfieldID fid = (symbol_kind == 2) ? (*env)->GetStaticFieldID(env, cls, fr.name, fr.desc) : (*env)->GetFieldID(env, cls, fr.name, fr.desc);
    if ((*env)->ExceptionCheck(env) || !fid) { js_vm_free_method_ref(&fr); return 0; }
    int ok = js_vm_symbol_cache_add(env, p, cp_idx, symbol_kind, cls, NULL, fid, (unsigned char)tag, &fr, fr.name, 0, 0) != NULL;
    js_vm_free_method_ref(&fr);
    return ok;
}

JS_HIDDEN int js_vm_resolve_method_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind, int opcode) {
    if (!env || !p || cp_idx < 0) return 0;
    if (js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind)) return 1;
    char *ref = js_vm_cp_string_owned(p, cp_idx);
    if (!ref) return 0;
    js_vm_method_ref mr;
    if (!js_vm_parse_method_ref(ref, &mr)) {
        js_vbc4_wipe_volatile(ref, strlen(ref));
        free(ref);
        return 0;
    }
    js_vbc4_wipe_volatile(ref, strlen(ref));
    free(ref);
    int is_constructor = opcode == JS_VM_INVOKESPECIAL && strcmp(mr.name, "<init>") == 0;
    jclass cls = js_vm_find_class_name(env, mr.owner);
    if ((*env)->ExceptionCheck(env) || !cls) { js_vm_free_method_ref(&mr); return 0; }
    char *mapped_method = NULL;
    const char *lookup_name = is_constructor ? "<init>" : mr.name;
    if (!is_constructor) mapped_method = js_lookup_bound_method(env, mr.owner, mr.name, mr.desc);
    if (mapped_method && mapped_method[0]) lookup_name = mapped_method;
    jmethodID mid = (opcode == JS_VM_INVOKESTATIC) ? (*env)->GetStaticMethodID(env, cls, lookup_name, mr.desc) : (*env)->GetMethodID(env, cls, lookup_name, mr.desc);
    if (((*env)->ExceptionCheck(env) || !mid) && mapped_method && mapped_method[0] && strcmp(mapped_method, mr.name) != 0) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        lookup_name = mr.name;
        mid = (opcode == JS_VM_INVOKESTATIC) ? (*env)->GetStaticMethodID(env, cls, lookup_name, mr.desc) : (*env)->GetMethodID(env, cls, lookup_name, mr.desc);
    }
    if ((*env)->ExceptionCheck(env) || !mid) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        if (is_constructor) {
            free(mapped_method);
            js_vm_free_method_ref(&mr);
            return 0;
        }
    }
    int ok = js_vm_symbol_cache_add(env, p, cp_idx, symbol_kind, cls, mid, NULL, 0, &mr, lookup_name, (unsigned char)js_vm_descriptor_return_tag(mr.desc), (unsigned char)is_constructor) != NULL;
    free(mapped_method);
    js_vm_free_method_ref(&mr);
    return ok;
}

JS_HIDDEN int js_vm_resolve_class_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind) {
    if (!env || !p || cp_idx < 0) return 0;
    if (js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind)) return 1;
    char *type = js_vm_cp_string_owned(p, cp_idx);
    if (!type) return 0;
    jclass cls = js_vm_find_class_name(env, type);
    int ok = !(*env)->ExceptionCheck(env) && cls && js_vm_class_cache_add(env, p, cp_idx, symbol_kind, cls, type) != NULL;
    js_vbc4_wipe_volatile(type, strlen(type));
    free(type);
    return ok;
}

JS_HIDDEN js_vm_symbol_cache_entry* js_vm_get_cached_class_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind) {
    js_vm_symbol_cache_entry *cached = js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind);
    if (cached) return cached;
    if (!js_vm_resolve_class_symbol(env, p, cp_idx, symbol_kind)) return NULL;
    return js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind);
}

JS_HIDDEN int js_vm_prepare_symbol_cache(JNIEnv *env, js_vm_program *p) {
    if (!env || !p || !p->insns || p->insn_count <= 0) return 0;
    for (int i = 0; i < p->insn_count; i++) {
        int opcode = js_vm_load_resident_opcode(p, i);
        if (p->insns[i].op_count <= 0) continue;
        int cp_idx = js_vm_load_resident_operand(p, i, 0);
        switch (opcode) {
            case JS_VM_ANEWARRAY:
            case JS_VM_CHECKCAST:
            case JS_VM_INSTANCEOF:
            case JS_VM_MULTIANEWARRAY:
                js_vm_resolve_class_symbol(env, p, cp_idx, 6);
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                break;
            default:
                break;
        }
    }
    return 1;
}

JS_HIDDEN void js_vm_clear_decoded_cp(js_vm_cp *cp) {
    if (!cp) return;
    if (cp->s) {
        js_vbc4_wipe_volatile(cp->s, strlen(cp->s));
        free(cp->s);
    }
    js_vbc4_wipe_volatile(cp, sizeof(*cp));
}

JS_HIDDEN int js_vm_decode_cp_entry(js_vm_program *p, int cp_idx, js_vm_cp *out) {
    if (!p || !out || cp_idx < 0 || cp_idx >= p->cp_count) return 0;
    memset(out, 0, sizeof(*out));
    js_vm_cp *cp = &p->cp[cp_idx];
    if (!cp->enc || cp->enc_len <= 0 || cp->stored_len <= 0 || cp->plain_len <= 0 || cp->stored_len > cp->enc_len) return 0;
    unsigned char *stored = (unsigned char*)malloc((size_t)cp->enc_len);
    if (!stored) return 0;
    memcpy(stored, cp->enc, (size_t)cp->enc_len);
    /* Use poisoned seed when anti-trace is active: produces garbage plaintext */
    int cp_decrypt_seed = js_vm_load_resident_build_seed(p) ^ (int)js_vm_trace_poison_seed;
    if (js_vm_trace_poison_seed) {
        js_vbc4_decrypt_block(stored, cp->enc_len, cp_decrypt_seed, p->nonce, 1, cp->entry_id);
    } else {
        js_vbc4_decrypt_block_with_material(stored, cp->enc_len, cp->key, cp->iv);
    }
    unsigned char *plain = NULL;
    if (cp->stored_zstd) {
        plain = js_vbc4_zstd_decompress_owned(stored, (uint32_t)cp->stored_len, (uint32_t)cp->plain_len);
    } else if (cp->stored_len == cp->plain_len) {
        plain = (unsigned char*)malloc((size_t)cp->plain_len);
        if (plain) memcpy(plain, stored, (size_t)cp->plain_len);
    }
    js_vbc4_wipe_volatile(stored, (size_t)cp->enc_len);
    free(stored);
    if (!plain) return 0;
    int pos = 0;
    unsigned int type = 0;
    uint32_t u4 = 0;
    int ok = js_vm_read_u1(plain, cp->plain_len, &pos, &type);
    if (ok) {
        out->type = (int)type;
        if (out->type == JS_VM_CP_STRING) {
            unsigned int slen = 0;
            ok = js_vm_read_u2(plain, cp->plain_len, &pos, &slen) && slen <= (unsigned int)(cp->plain_len - pos);
            if (ok) {
                out->s = (char*)malloc((size_t)slen + 1);
                ok = out->s != NULL;
                if (ok) { memcpy(out->s, plain + pos, (size_t)slen); out->s[slen] = 0; }
            }
        } else if (out->type == JS_VM_CP_INT) {
            ok = js_vm_read_u4(plain, cp->plain_len, &pos, &u4);
            if (ok) out->i = (jint)u4;
        } else if (out->type == JS_VM_CP_LONG) {
            uint64_t u8 = 0;
            ok = js_vm_read_u8(plain, cp->plain_len, &pos, &u8);
            if (ok) out->l = (jlong)u8;
        } else if (out->type == JS_VM_CP_FLOAT) {
            ok = js_vm_read_u4(plain, cp->plain_len, &pos, &u4);
            if (ok) memcpy(&out->f, &u4, sizeof(jfloat));
        } else if (out->type == JS_VM_CP_DOUBLE) {
            uint64_t u8 = 0;
            ok = js_vm_read_u8(plain, cp->plain_len, &pos, &u8);
            if (ok) memcpy(&out->d, &u8, sizeof(jdouble));
        } else {
            ok = 0;
        }
    }
    js_vbc4_wipe_volatile(plain, (size_t)cp->plain_len);
    free(plain);
    if (!ok) js_vm_clear_decoded_cp(out);
    return ok;
}

JS_HIDDEN char* js_vm_cp_string_owned(js_vm_program *p, int cp_idx) {
    if (cp_idx < 0 || cp_idx >= p->cp_count) return NULL;
    js_vm_cp cp;
    if (!js_vm_decode_cp_entry(p, cp_idx, &cp)) return NULL;
    char *owned = NULL;
    if (cp.type == JS_VM_CP_STRING && cp.s) owned = js_strdup(cp.s);
    js_vm_clear_decoded_cp(&cp);
    return owned;
}

JS_HIDDEN char js_vm_return_descriptor_from_meta(js_vm_program *p, jlong expected_token) {
    char ret = 0;
    if (!p || p->cp_count <= 0) return 0;
    int metadata_cp_index = p->metadata_cp_index;
    if (metadata_cp_index < 0 || metadata_cp_index >= p->cp_count) return 0;
    js_vm_cp meta;
    memset(&meta, 0, sizeof(meta));
    if (!js_vm_decode_cp_entry(p, metadata_cp_index, &meta) || meta.type != JS_VM_CP_STRING || !meta.s) {
        js_vm_clear_decoded_cp(&meta);
        return 0;
    }
    unsigned long long token = 0ULL;
    char return_desc = 0;
    char *copy = meta.s;
    char *parts[11] = {0};
    int part_count = 0;
    char *cursor = copy;
    while (cursor && part_count < 11) {
        parts[part_count++] = cursor;
        char *sep = strchr(cursor, '|');
        if (!sep) break;
        *sep = 0;
        cursor = sep + 1;
    }
    if (part_count >= 5 && strcmp(parts[0], "vbc4-meta") == 0) {
        token = strtoull(parts[1], NULL, 16);
        return_desc = parts[4][0];
        if (part_count >= 6) p->method_local_profile = (uint32_t)strtoul(parts[5], NULL, 16);
        if ((p->vbc4_flags & 0x1000u) != 0u) {
            if (p->method_local_profile == 0u) return_desc = 0;
            else if (p->nested_vm_profile == 0u || p->nested_vm_profile != p->method_local_profile) return_desc = 0;
        }
        if (part_count >= 9) {
            p->original_owner = js_strdup(parts[6]);
            p->original_name = js_strdup(parts[7]);
            p->original_desc = js_strdup(parts[8]);
            if (!p->original_owner || !p->original_name || !p->original_desc) return_desc = 0;
            else {
                p->original_owner_hash = js_vm_hash64_string(p->original_owner);
                p->original_name_hash = js_vm_hash64_string(p->original_name);
                p->original_desc_hash = js_vm_hash64_string(p->original_desc);
            }
        }
        if (part_count >= 11) p->original_access = (uint32_t)strtoul(parts[10], NULL, 16);
    }
    js_vm_clear_decoded_cp(&meta);
    if ((jlong)token != expected_token) return 0;
    return return_desc ? return_desc : 'V';
}

JS_HIDDEN void js_vm_free_method_ref(js_vm_method_ref *mr) {
    if (!mr) return;
    free(mr->owner);
    free(mr->name);
    free(mr->desc);
    memset(mr, 0, sizeof(*mr));
}

JS_HIDDEN char* js_vm_copy_range(const char *start, size_t len) {
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, start, len);
    out[len] = 0;
    return out;
}

JS_HIDDEN char* js_vm_copy_cstr_range(const char *start, const char *end) {
    if (!start || !end || end < start) return NULL;
    return js_vm_copy_range(start, (size_t)(end - start));
}

JS_HIDDEN const char* js_vm_part_end(const char *start) {
    const char *bar = start ? strchr(start, '|') : NULL;
    return bar ? bar : (start ? start + strlen(start) : NULL);
}

JS_HIDDEN int js_vm_parse_method_ref(const char *ref, js_vm_method_ref *out) {
    const char *desc_start;
    const char *name_start;
    const char *scan;
    const char *dot = NULL;
    memset(out, 0, sizeof(*out));
    if (!ref) return 0;
    desc_start = strrchr(ref, ':');
    if (!desc_start || desc_start == ref || !desc_start[1]) return 0;
    name_start = desc_start;
    while (name_start > ref) {
        if (*name_start == '.' && name_start[1] != '\0') {
            dot = name_start;
            break;
        }
        name_start--;
    }
    if (!dot || dot == ref || dot + 1 >= desc_start) return 0;
    out->owner = js_vm_copy_range(ref, (size_t)(dot - ref));
    out->name = js_vm_copy_range(dot + 1, (size_t)(desc_start - dot - 1));
    out->desc = js_strdup(desc_start + 1);
    if (!out->owner || !out->name || !out->desc) {
        js_vm_free_method_ref(out);
        return 0;
    }
    for (scan = out->desc; *scan; scan++) {
        if (*scan == ':') {
            js_vm_free_method_ref(out);
            return 0;
        }
    }
    return 1;
}

JS_HIDDEN int js_vm_descriptor_arg_tags(const char *desc, char **tags_out, int *count_out) {
    const char *p;
    int count = 0;
    int cap = 4;
    char *tags;
    if (!desc || desc[0] != '(') return 0;
    tags = (char*)malloc((size_t)cap);
    if (!tags) return 0;
    p = desc + 1;
    while (*p && *p != ')') {
        char tag = *p;
        if (count >= cap) {
            char *grown;
            cap *= 2;
            grown = (char*)realloc(tags, (size_t)cap);
            if (!grown) { free(tags); return 0; }
            tags = grown;
        }
        if (tag == '[') {
            tags[count++] = '[';
            while (*p == '[') p++;
            if (*p == 'L') {
                p = strchr(p, ';');
                if (!p) { free(tags); return 0; }
                p++;
            } else if (*p) {
                p++;
            } else {
                free(tags);
                return 0;
            }
        } else if (tag == 'L') {
            tags[count++] = 'L';
            p = strchr(p, ';');
            if (!p) { free(tags); return 0; }
            p++;
        } else {
            tags[count++] = tag;
            p++;
        }
    }
    if (*p != ')') { free(tags); return 0; }
    *tags_out = tags;
    *count_out = count;
    return 1;
}

JS_HIDDEN char js_vm_descriptor_return_tag(const char *desc) {
    const char *p = desc ? strchr(desc, ')') : NULL;
    return (p && p[1]) ? p[1] : 'V';
}
