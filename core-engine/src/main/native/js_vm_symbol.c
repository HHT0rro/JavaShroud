#include "js_vm_symbol.h"
#include "js_crypto.h"
#include "js_vm_core.h"
#include "js_vm_resource.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const unsigned char JS_VM_METHOD_IDENTITY_DOMAIN[] = "javashroud-vbc4-method-identity-v2";
static const unsigned char JS_VM_OWNER_IDENTITY_DOMAIN[] = "javashroud-vbc4-owner-identity-v2";
static const unsigned char JS_VM_CP_STRING_KEY_DOMAIN[] = "javashroud-vbc4-cp-string-key-v1";
static const unsigned char JS_VM_CP_STRING_IV_DOMAIN[] = "javashroud-vbc4-cp-string-iv-v1";
static const unsigned char JS_VM_CP_STRING_TAG_DOMAIN[] = "javashroud-vbc4-cp-string-tag-v1";

static int js_vm_hex_identity(const char *hex, unsigned char out[32]) {
    if (!hex || strlen(hex) != 64u || !out) return 0;
    unsigned char decoded[32] = {0};
    for (int i = 0; i < 32; i++) {
        unsigned char hi = (unsigned char)hex[i * 2];
        unsigned char lo = (unsigned char)hex[i * 2 + 1];
        int h = hi >= '0' && hi <= '9' ? hi - '0' : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : -1;
        int l = lo >= '0' && lo <= '9' ? lo - '0' : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : -1;
        if (h < 0 || l < 0) { js_vbc4_wipe_volatile(decoded, sizeof(decoded)); return 0; }
        decoded[i] = (unsigned char)((h << 4) | l);
    }
    memcpy(out, decoded, sizeof(decoded));
    js_vbc4_wipe_volatile(decoded, sizeof(decoded));
    return 1;
}

static int js_vm_parse_hex_u64_strict(const char *text, unsigned long long *out) {
    uint64_t value = 0u;
    if (!text || !text[0] || !out) return 0;
    for (const unsigned char *cursor = (const unsigned char*)text; *cursor; cursor++) {
        unsigned int nibble;
        if (*cursor >= '0' && *cursor <= '9') nibble = (unsigned int)(*cursor - '0');
        else if (*cursor >= 'a' && *cursor <= 'f') nibble = (unsigned int)(*cursor - 'a' + 10);
        else if (*cursor >= 'A' && *cursor <= 'F') nibble = (unsigned int)(*cursor - 'A' + 10);
        else return 0;
        if (value > (UINT64_MAX - nibble) / 16u) return 0;
        value = value * 16u + nibble;
    }
    *out = (unsigned long long)value;
    return 1;
}

static int js_vm_parse_hex_u32_strict(const char *text, uint32_t *out) {
    unsigned long long value = 0ULL;
    if (!out || !js_vm_parse_hex_u64_strict(text, &value) || value > UINT32_MAX) return 0;
    *out = (uint32_t)value;
    return 1;
}

static int js_vm_valid_return_tag(const char *text) {
    return text && text[0] && text[1] == 0 && strchr("VZBCSIJFDL[", text[0]) != NULL;
}

static int js_vm_valid_argument_tags(const char *text, size_t *out_count) {
    if (!text || !out_count) return 0;
    size_t count = strlen(text);
    if (count > 65535u) return 0;
    for (size_t i = 0; i < count; i++) {
        if (!strchr("ZBCSIJFDL[", text[i])) return 0;
    }
    *out_count = count;
    return 1;
}

static int js_vm_keyed_identity(const unsigned char *domain, int domain_len, const unsigned char **parts, const int *lens, int part_count, unsigned char out[32]) {
    unsigned char build_key[32];
    if (!domain || domain_len <= 0 || !parts || !lens || part_count <= 0 || !out) return 0;
    if (!js_vm_copy_runtime_build_key(build_key)) return 0;
    const unsigned char separator = 0;
    const unsigned char *framed[8];
    int framed_lens[8];
    int count = 0;
    framed[count] = domain; framed_lens[count++] = domain_len;
    for (int i = 0; i < part_count && count + 1 < 8; i++) {
        framed[count] = &separator; framed_lens[count++] = 1;
        framed[count] = parts[i]; framed_lens[count++] = lens[i];
    }
    js_hmac_sha256_with_key(build_key, 32, framed, framed_lens, count, out);
    js_vbc4_wipe_volatile(build_key, sizeof(build_key));
    return 1;
}

JS_HIDDEN int js_vm_method_identity_for_ref(const js_vm_method_ref *ref, unsigned char out[32]) {
    if (!ref || !ref->owner || !ref->name || !ref->desc) return 0;
    const unsigned char *parts[3] = { (const unsigned char*)ref->owner, (const unsigned char*)ref->name, (const unsigned char*)ref->desc };
    int lens[3] = { (int)strlen(ref->owner), (int)strlen(ref->name), (int)strlen(ref->desc) };
    return js_vm_keyed_identity(JS_VM_METHOD_IDENTITY_DOMAIN, (int)(sizeof(JS_VM_METHOD_IDENTITY_DOMAIN) - 1), parts, lens, 3, out);
}

JS_HIDDEN int js_vm_owner_identity_for_name(const char *owner, unsigned char out[32]) {
    if (!owner || !owner[0]) return 0;
    const unsigned char *parts[1] = { (const unsigned char*)owner };
    int lens[1] = { (int)strlen(owner) };
    return js_vm_keyed_identity(JS_VM_OWNER_IDENTITY_DOMAIN, (int)(sizeof(JS_VM_OWNER_IDENTITY_DOMAIN) - 1), parts, lens, 1, out);
}

static int js_vm_valid_symbol_method_name(const char *name) {
    if (!name || !name[0]) return 0;
    if (strcmp(name, "<init>") == 0 || strcmp(name, "<clinit>") == 0) return 1;
    for (const unsigned char *p = (const unsigned char*)name; *p; p++) {
        if (*p <= 0x20u || *p >= 0x7fu || *p == '.' || *p == '/' || *p == ';' || *p == '[' || *p == '(' || *p == ')') return 0;
    }
    return 1;
}

static int js_vm_valid_symbol_method_lookup(const char *name, const char *desc) {
    char *tags = NULL;
    int argc = 0;
    if (!js_vm_valid_symbol_method_name(name) || !desc || !desc[0]) return 0;
    if (strlen(name) > 512u || strlen(desc) > 4096u) return 0;
    if (!js_vm_descriptor_arg_tags(desc, &tags, &argc)) return 0;
    free(tags);
    return argc >= 0 && js_vm_descriptor_return_tag(desc) != 0;
}

static char* js_vm_bounded_lookup_copy(const char *value, size_t max_len) {
    if (!value || max_len == 0) return NULL;
    size_t len = 0;
    while (len <= max_len && value[len]) len++;
    if (len == 0 || len > max_len) return NULL;
    char *copy = (char*)malloc(len + 1u);
    if (!copy) return NULL;
    memcpy(copy, value, len);
    copy[len] = 0;
    return copy;
}

static jmethodID js_vm_lookup_method_id(JNIEnv *env, jclass cls, const char *name, const char *desc, int is_static) {
    if (!env || !cls || !js_vm_valid_symbol_method_lookup(name, desc)) return NULL;
    char *safe_name = js_vm_bounded_lookup_copy(name, 512u);
    char *safe_desc = js_vm_bounded_lookup_copy(desc, 4096u);
    if (!safe_name || !safe_desc) {
        free(safe_name);
        free(safe_desc);
        return NULL;
    }
    jmethodID mid = is_static ? (*env)->GetStaticMethodID(env, cls, safe_name, safe_desc) : (*env)->GetMethodID(env, cls, safe_name, safe_desc);
    js_vbc4_wipe_volatile(safe_name, strlen(safe_name));
    js_vbc4_wipe_volatile(safe_desc, strlen(safe_desc));
    free(safe_name);
    free(safe_desc);
    return mid;
}

static js_vm_program *js_vm_symbol_owner(js_vm_program *p) {
    return (p && p->symbol_cache_owner) ? p->symbol_cache_owner : p;
}

static int js_vm_symbol_cache_reserve(js_vm_program *owner) {
    if (owner->symbols) return 1;
    int capacity = owner->cp_count * 2 + 16;
    if (capacity < 32) capacity = 32;
    owner->symbols = (js_vm_symbol_cache_entry*)calloc((size_t)capacity, sizeof(js_vm_symbol_cache_entry));
    if (!owner->symbols) return 0;
    owner->symbol_capacity = capacity;
    owner->symbol_count = 0;
    return 1;
}

JS_HIDDEN js_vm_symbol_cache_entry* js_vm_symbol_cache_lookup(js_vm_program *p, int cp_idx, int kind) {
    js_vm_program *owner = js_vm_symbol_owner(p);
    if (!owner || !owner->symbols || owner->symbol_count <= 0) return NULL;
    for (int i = 0; i < owner->symbol_count; i++) {
        if (owner->symbols[i].cp_idx == cp_idx && owner->symbols[i].kind == kind) return &owner->symbols[i];
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
    js_vm_program *owner = js_vm_symbol_owner(p);
    js_vm_symbol_cache_lock_enter();
    js_vm_symbol_cache_entry *existing = js_vm_symbol_cache_lookup(p, cp_idx, kind);
    if (existing) { js_vm_symbol_cache_lock_leave(); return existing; }
    if (!js_vm_symbol_cache_reserve(owner) || owner->symbol_count >= owner->symbol_capacity) {
        js_vm_symbol_cache_lock_leave();
        return NULL;
    }
    js_vm_symbol_cache_entry *slot = &owner->symbols[owner->symbol_count];
    memset(slot, 0, sizeof(*slot));
    slot->cp_idx = cp_idx;
    slot->kind = kind;
    slot->cls = (jclass)(*env)->NewGlobalRef(env, cls);
    if ((*env)->ExceptionCheck(env) || !slot->cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        memset(slot, 0, sizeof(*slot));
        js_vm_symbol_cache_lock_leave();
        return NULL;
    }
    slot->type_name = js_strdup(type_name);
    if (!slot->type_name) {
        js_vm_symbol_cache_clear_entry(env, slot);
        js_vm_symbol_cache_lock_leave();
        return NULL;
    }
    owner->symbol_count++;
    js_vm_symbol_cache_lock_leave();
    return slot;
}

JS_HIDDEN js_vm_symbol_cache_entry* js_vm_symbol_cache_add(JNIEnv *env, js_vm_program *p, int cp_idx, int kind, jclass cls, jmethodID mid, jfieldID fid, unsigned char tag, const js_vm_method_ref *ref, const char *lookup_name, unsigned char ret_tag, unsigned char is_constructor) {
    if (!env || !p || !cls || !ref || !ref->owner || !ref->name || !ref->desc) return NULL;
    js_vm_program *owner = js_vm_symbol_owner(p);
    js_vm_symbol_cache_lock_enter();
    js_vm_symbol_cache_entry *existing = js_vm_symbol_cache_lookup(p, cp_idx, kind);
    if (existing) { js_vm_symbol_cache_lock_leave(); return existing; }
    if (!js_vm_symbol_cache_reserve(owner) || owner->symbol_count >= owner->symbol_capacity) {
        js_vm_symbol_cache_lock_leave();
        return NULL;
    }
    js_vm_symbol_cache_entry *slot = &owner->symbols[owner->symbol_count];
    memset(slot, 0, sizeof(*slot));
    slot->cp_idx = cp_idx;
    slot->kind = kind;
    slot->cls = (jclass)(*env)->NewGlobalRef(env, cls);
    if ((*env)->ExceptionCheck(env) || !slot->cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        memset(slot, 0, sizeof(*slot));
        js_vm_symbol_cache_lock_leave();
        return NULL;
    }
    slot->mid = mid;
    slot->fid = fid;
    slot->tag = tag;
    unsigned char ref_identity[32];
    if (js_vm_method_identity_for_ref(ref, ref_identity)) {
        memcpy(slot->method_identity, ref_identity, sizeof(slot->method_identity));
    }
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
    if (kind == 4 || kind == 5) {
        slot->is_self_call = (unsigned char)(js_vm_method_identity_for_ref(ref, ref_identity) &&
            memcmp(ref_identity, p->method_identity, sizeof(ref_identity)) == 0);
    } else slot->is_self_call = 0;
    js_vbc4_wipe_volatile(ref_identity, sizeof(ref_identity));
    if (kind == 4 || kind == 5) {
        char *tags = NULL;
        int parsed_argc = 0;
        if (!js_vm_descriptor_arg_tags(ref->desc, &tags, &parsed_argc)) {
            js_vm_symbol_cache_clear_entry(env, slot);
            js_vm_symbol_cache_lock_leave();
            return NULL;
        }
        slot->arg_tags = tags;
        slot->argc = parsed_argc;
    }
    owner->symbol_count++;
    js_vm_symbol_cache_lock_leave();
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
    jmethodID mid = js_vm_lookup_method_id(env, cls, lookup_name, mr.desc, opcode == JS_VM_INVOKESTATIC);
    if (((*env)->ExceptionCheck(env) || !mid) && mapped_method && mapped_method[0] && strcmp(mapped_method, mr.name) != 0 && js_vm_valid_symbol_method_lookup(mr.name, mr.desc)) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        lookup_name = mr.name;
        mid = js_vm_lookup_method_id(env, cls, lookup_name, mr.desc, opcode == JS_VM_INVOKESTATIC);
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
        if (out->type == JS_VM_CP_SEALED_STRING) {
            unsigned int version = 0, slen = 0;
            unsigned char build_key[32] = {0}, key_material[32] = {0}, iv_material[32] = {0}, expected_tag[32] = {0};
            unsigned char key[16] = {0}, iv[16] = {0};
            ok = js_vm_read_u1(plain, cp->plain_len, &pos, &version) && version == 1u && pos + 16 <= cp->plain_len;
            const unsigned char *nonce = ok ? plain + pos : NULL;
            if (ok) pos += 16;
            if (ok) ok = js_vm_read_u2(plain, cp->plain_len, &pos, &slen);
            if (ok) {
                int remaining = cp->plain_len - pos;
                ok = remaining >= 32 && slen == (unsigned int)(remaining - 32);
            }
            const unsigned char *ciphertext = ok ? plain + pos : NULL;
            const unsigned char *stored_tag = ok ? plain + pos + slen : NULL;
            if (ok) ok = js_vm_copy_runtime_build_key(build_key);
            if (ok) {
                const unsigned char *key_parts[2] = { JS_VM_CP_STRING_KEY_DOMAIN, nonce };
                const int key_lens[2] = { (int)(sizeof(JS_VM_CP_STRING_KEY_DOMAIN) - 1), 16 };
                js_hmac_sha256_with_key(build_key, 32, key_parts, key_lens, 2, key_material);
                const unsigned char *iv_parts[2] = { JS_VM_CP_STRING_IV_DOMAIN, nonce };
                const int iv_lens[2] = { (int)(sizeof(JS_VM_CP_STRING_IV_DOMAIN) - 1), 16 };
                js_hmac_sha256_with_key(build_key, 32, iv_parts, iv_lens, 2, iv_material);
                const unsigned char *tag_parts[3] = { JS_VM_CP_STRING_TAG_DOMAIN, nonce, ciphertext };
                const int tag_lens[3] = { (int)(sizeof(JS_VM_CP_STRING_TAG_DOMAIN) - 1), 16, (int)slen };
                js_hmac_sha256_with_key(build_key, 32, tag_parts, tag_lens, 3, expected_tag);
                unsigned char diff = 0;
                for (int i = 0; i < 32; i++) diff |= (unsigned char)(expected_tag[i] ^ stored_tag[i]);
                ok = diff == 0;
            }
            if (ok) {
                memcpy(key, key_material, sizeof(key));
                memcpy(iv, iv_material, sizeof(iv));
                out->s = (char*)malloc((size_t)slen + 1u);
                ok = out->s != NULL;
                if (ok) {
                    memcpy(out->s, ciphertext, (size_t)slen);
                    js_vbc4_decrypt_block_with_material((unsigned char*)out->s, (int)slen, key, iv);
                    out->s[slen] = 0;
                    out->type = JS_VM_CP_STRING;
                }
            }
            js_vbc4_wipe_volatile(build_key, sizeof(build_key));
            js_vbc4_wipe_volatile(key_material, sizeof(key_material));
            js_vbc4_wipe_volatile(iv_material, sizeof(iv_material));
            js_vbc4_wipe_volatile(expected_tag, sizeof(expected_tag));
            js_vbc4_wipe_volatile(key, sizeof(key));
            js_vbc4_wipe_volatile(iv, sizeof(iv));
        } else if (out->type == JS_VM_CP_STRING) {
            /* Current artifacts never accept seed-only string plaintext. */
            ok = 0;
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
    uint32_t method_local_profile = 0u;
    uint32_t native_vm_profile_id = 0u;
    uint32_t dispatch_profile_tag = 0u;
    unsigned char method_identity[32] = {0};
    unsigned char owner_identity[32] = {0};
    char return_desc = 0;
    unsigned char is_static = 0;
    char *argument_tags = NULL;
    int argument_count = 0;
    char *resource_path = NULL;
    int ok = 0;
    size_t metadata_length = strlen(meta.s);
    char *copy = js_strdup(meta.s);
    if (!copy) {
        js_vm_clear_decoded_cp(&meta);
        return 0;
    }
    char *parts[11] = {0};
    int part_count = 0;
    char *cursor = copy;
    while (cursor) {
        if (part_count == 11) {
            /* Reject trailing fields instead of silently accepting a prefix. */
            part_count = 12;
            break;
        }
        parts[part_count++] = cursor;
        char *sep = strchr(cursor, '|');
        if (!sep) break;
        *sep = 0;
        cursor = sep + 1;
    }
    if (part_count == 11 && strcmp(parts[0], "vbc4-meta-v2") == 0) {
        size_t argument_count_size = 0u;
        ok = js_vm_parse_hex_u64_strict(parts[1], &token) &&
            (jlong)token == expected_token &&
            js_vm_valid_return_tag(parts[2]) &&
            js_vm_parse_hex_u32_strict(parts[3], &method_local_profile) &&
            js_vm_hex_identity(parts[4], method_identity) &&
            js_vm_hex_identity(parts[5], owner_identity) &&
            js_vm_valid_argument_tags(parts[6], &argument_count_size) &&
            parts[7][0] != 0 &&
            (strcmp(parts[8], "0") == 0 || strcmp(parts[8], "1") == 0) &&
            js_vm_parse_hex_u32_strict(parts[9], &native_vm_profile_id) &&
            js_vm_parse_hex_u32_strict(parts[10], &dispatch_profile_tag) &&
            dispatch_profile_tag != 0u;
        if (ok && (p->vbc4_flags & 0x1000u) != 0u) {
            ok = method_local_profile != 0u && p->nested_vm_profile != 0u && p->nested_vm_profile == method_local_profile;
        }
        if (ok) {
            return_desc = parts[2][0];
            is_static = (unsigned char)(parts[8][0] == '1');
            argument_count = (int)argument_count_size;
            argument_tags = (char*)malloc(argument_count_size + 1u);
            resource_path = js_strdup(parts[7]);
            ok = argument_tags != NULL && resource_path != NULL;
            if (ok) memcpy(argument_tags, parts[6], argument_count_size + 1u);
        }
        if (!ok) {
            if (argument_tags) { js_vbc4_wipe_volatile(argument_tags, argument_count_size + 1u); free(argument_tags); argument_tags = NULL; }
            if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); resource_path = NULL; }
        }
    }
    js_vm_clear_decoded_cp(&meta);
    js_vbc4_wipe_volatile(copy, metadata_length);
    free(copy);
    if (!ok) {
        if (argument_tags) { js_vbc4_wipe_volatile(argument_tags, (size_t)argument_count + 1u); free(argument_tags); }
        if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); }
        js_vbc4_wipe_volatile(method_identity, sizeof(method_identity));
        js_vbc4_wipe_volatile(owner_identity, sizeof(owner_identity));
        return 0;
    }

    /* Publish only after every authenticated field has parsed successfully. */
    if (p->argument_tags || p->resource_path) {
        if (argument_tags) { js_vbc4_wipe_volatile(argument_tags, (size_t)argument_count + 1u); free(argument_tags); }
        if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); }
        js_vbc4_wipe_volatile(method_identity, sizeof(method_identity));
        js_vbc4_wipe_volatile(owner_identity, sizeof(owner_identity));
        return 0;
    }
    p->method_local_profile = method_local_profile;
    p->native_vm_profile_id = native_vm_profile_id;
    p->dispatch_profile_tag = dispatch_profile_tag;
    p->return_desc = return_desc;
    memcpy(p->method_identity, method_identity, sizeof(method_identity));
    memcpy(p->owner_identity, owner_identity, sizeof(owner_identity));
    p->argument_tags = argument_tags;
    p->argument_count = argument_count;
    p->resource_path = resource_path;
    p->is_static = is_static;
    js_vbc4_wipe_volatile(method_identity, sizeof(method_identity));
    js_vbc4_wipe_volatile(owner_identity, sizeof(owner_identity));
    return return_desc;
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
