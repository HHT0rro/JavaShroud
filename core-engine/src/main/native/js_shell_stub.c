#include "js_shell_stub.h"
#include "js_shell_loader.h"
#include "js_shell_crypto.h"
#include "js_shell_payload.inc"
#include "zstd.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#endif

static js_shell_loaded_image g_inner_image;
static const js_native_abi_table *g_inner_abi = 0;
static JavaVM *g_shell_vm = 0;
static volatile int g_shell_loaded = 0;
static volatile int g_shell_failed = 0;
static volatile int g_inner_onload_done = 0;
static volatile const char g_js_shell_stub_marker[] = JS_NATIVE_MAX_STUB_MARKER;

#define JS_SHELL_MANUAL_MAP_RESERVED ((void *)(uintptr_t)0x4A5353484D4D4150ULL)

#define JS_SHELL_COMPRESSION_NONE 0u
#define JS_SHELL_COMPRESSION_ZSTD 1u

typedef struct js_shell_payload_meta {
    unsigned int original_size;
    unsigned int stored_size;
    unsigned int encoded_size;
    unsigned int compression_codec;
    unsigned int chunk_size;
    unsigned int chunk_count;
    unsigned int layout_profile;
    unsigned int dispatcher_profile;
    const unsigned char *chunk_tags;
    size_t chunk_tags_size;
    unsigned char nonce[16];
} js_shell_payload_meta;

static unsigned int js_shell_read_u32_le(const unsigned char *bytes, size_t size, size_t *offset, unsigned int *out) {
    if (!bytes || !offset || !out || *offset > size || size - *offset < 4u) return 0;
    *out = (unsigned int)bytes[*offset] |
        ((unsigned int)bytes[*offset + 1u] << 8) |
        ((unsigned int)bytes[*offset + 2u] << 16) |
        ((unsigned int)bytes[*offset + 3u] << 24);
    *offset += 4u;
    return 1;
}

static unsigned int js_shell_skip_string(const unsigned char *bytes, size_t size, size_t *offset) {
    unsigned int length = 0;
    if (!js_shell_read_u32_le(bytes, size, offset, &length)) return 0;
    if (*offset > size || (size_t)length > size - *offset) return 0;
    *offset += (size_t)length;
    return 1;
}

static int js_shell_header_has_marker(void) {
    const char marker[] = JS_NATIVE_MAX_PAYLOAD_MARKER;
    if (g_js_shell_stub_marker[0] != 'J') return 0;
    const size_t marker_len = sizeof(marker) - 1u;
    if (JS_SHELL_PAYLOAD_HEADER_SIZE <= marker_len) return 0;
    return memcmp(js_shell_payload_header, marker, marker_len) == 0 && js_shell_payload_header[marker_len] == 0;
}

static int js_shell_extract_meta(js_shell_payload_meta *meta) {
    size_t offset = 0;
    unsigned int version = 0, level = 0, nonce_size = 0, chunk_tags_size = 0;
    if (!meta) return 0;
    memset(meta, 0, sizeof(*meta));
    while (offset < JS_SHELL_PAYLOAD_HEADER_SIZE && js_shell_payload_header[offset] != 0) offset++;
    if (offset >= JS_SHELL_PAYLOAD_HEADER_SIZE) return 0;
    offset++;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &version)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &level)) return 0;
    if (!js_shell_skip_string(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset)) return 0;
    if (!js_shell_skip_string(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset)) return 0;
    if (!js_shell_skip_string(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->original_size)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->stored_size)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->encoded_size)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->compression_codec)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->chunk_size)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->chunk_count)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &nonce_size)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->layout_profile)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &meta->dispatcher_profile)) return 0;
    if (version != JS_SHELL_PROTOCOL_VERSION || level != 2u || meta->encoded_size != JS_SHELL_PAYLOAD_SIZE || nonce_size != 16u) return 0;
    if (meta->original_size != JS_SHELL_ORIGINAL_PAYLOAD_SIZE || meta->stored_size != JS_SHELL_STORED_PAYLOAD_SIZE) return 0;
    if (meta->compression_codec != JS_SHELL_COMPRESSION_CODEC || meta->chunk_size != JS_SHELL_CHUNK_SIZE || meta->chunk_count != JS_SHELL_CHUNK_COUNT) return 0;
    if (meta->compression_codec != JS_SHELL_COMPRESSION_NONE && meta->compression_codec != JS_SHELL_COMPRESSION_ZSTD) return 0;
    if (meta->layout_profile != JS_SHELL_LAYOUT_PROFILE || meta->dispatcher_profile != JS_SHELL_DISPATCHER_PROFILE) return 0;
    if (meta->chunk_size == 0u || meta->chunk_count != (meta->encoded_size == 0u ? 0u : (meta->encoded_size + meta->chunk_size - 1u) / meta->chunk_size)) return 0;
    if (offset > JS_SHELL_PAYLOAD_HEADER_SIZE || JS_SHELL_PAYLOAD_HEADER_SIZE - offset < 16u) return 0;
    memcpy(meta->nonce, js_shell_payload_header + offset, 16u);
    offset += 16u;
    if (JS_SHELL_PAYLOAD_HEADER_SIZE - offset < 96u) return 0;
    offset += 96u;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &chunk_tags_size)) return 0;
    if (chunk_tags_size != meta->chunk_count * 4u) return 0;
    if (offset > JS_SHELL_PAYLOAD_HEADER_SIZE || (size_t)chunk_tags_size > JS_SHELL_PAYLOAD_HEADER_SIZE - offset) return 0;
    meta->chunk_tags = js_shell_payload_header + offset;
    meta->chunk_tags_size = (size_t)chunk_tags_size;
    offset += (size_t)chunk_tags_size;
    return meta->original_size != 0u && meta->stored_size != 0u && offset == JS_SHELL_PAYLOAD_HEADER_SIZE;
}

static int js_shell_verify_payload(js_shell_payload_meta *meta) {
    unsigned char mac[32];
    unsigned int tag_acc = 0;
    if (!js_shell_header_has_marker()) return 0;
    if (JS_SHELL_PAYLOAD_SIZE == 0) return 0;
    if (sizeof(js_shell_payload_mac) != 32u || sizeof(js_shell_stream_key) != 32u) return 0;
    if (!js_shell_extract_meta(meta)) return 0;
    for (size_t i = 0; i < sizeof(js_shell_binding_tag); i++) tag_acc |= (unsigned int)js_shell_binding_tag[i];
    if (tag_acc == 0u) return 0;
    memset(mac, 0, sizeof(mac));
    js_shell_mac32(js_shell_stream_key, sizeof(js_shell_stream_key), js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, js_shell_payload_bytes, JS_SHELL_PAYLOAD_SIZE, js_shell_binding_tag, sizeof(js_shell_binding_tag), mac);
    return js_shell_consttime_equal(mac, js_shell_payload_mac, sizeof(mac));
}

static void js_shell_wipe_free(unsigned char *bytes, size_t size) {
    if (!bytes) return;
    volatile unsigned char *p = (volatile unsigned char *)bytes;
    while (size--) *p++ = 0;
#if defined(_WIN32)
    HeapFree(GetProcessHeap(), 0, bytes);
#else
    free(bytes);
#endif
}

static unsigned char *js_shell_alloc(size_t size) {
    if (size == 0u) return 0;
#if defined(_WIN32)
    return (unsigned char *)HeapAlloc(GetProcessHeap(), 0, size);
#else
    return (unsigned char *)malloc(size);
#endif
}

static jint js_shell_fail_onload(void) {
    const char *debug = getenv("JAVASHROUD_DEBUG_NATIVE_LOAD");
    if (debug && debug[0] && debug[0] != '0') {
        const char *reason = js_shell_loader_failure_reason();
        if (reason && reason[0]) fprintf(stderr, "JavaShroud max native shell load failed: %s\n", reason);
    }
    g_shell_failed = 1;
    return JNI_ERR;
}

static unsigned long long js_shell_fnv1a64(const char *value, unsigned long long hash) {
    if (!value) return hash;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        hash ^= (unsigned long long)(*p);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static char *js_shell_strdup(const char *value) {
    if (!value) return 0;
    size_t len = strlen(value);
    char *out = (char *)malloc(len + 1u);
    if (!out) return 0;
    memcpy(out, value, len + 1u);
    return out;
}

static void js_shell_native_init_name(char out[11]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Init", 5u);
}

static void js_shell_native_verify_name(char out[13]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Verify", 7u);
}

static void js_shell_native_heartbeat_name(char out[16]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Heartbeat", 10u);
}

static void js_shell_native_version_name(char out[17]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Get", 3u);
    memcpy(out + 9u, "Version", 8u);
}

static void js_shell_native_boot_token_name(char out[19]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Get", 3u);
    memcpy(out + 9u, "Boot", 4u);
    memcpy(out + 13u, "Token", 6u);
}

static void js_shell_native_runtime_key_name(char out[32]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Install", 7u);
    memcpy(out + 13u, "RuntimeResource", 15u);
    memcpy(out + 28u, "Key", 4u);
}

static void js_shell_native_preload_name(char out[30]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Preload", 7u);
    memcpy(out + 13u, "Runtime", 7u);
    memcpy(out + 20u, "Resources", 10u);
}

static void js_shell_native_decrypt_aes_name(char out[17]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Decrypt", 7u);
    memcpy(out + 13u, "Aes", 4u);
}

static void js_shell_native_class_key_name(char out[31]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Derive", 6u);
    memcpy(out + 12u, "ClassEncryption", 15u);
    memcpy(out + 27u, "Key", 4u);
}

static void js_shell_native_execute_name(char out[24]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Execute", 7u);
    memcpy(out + 13u, "Vm", 2u);
    memcpy(out + 15u, "Resource", 9u);
}

static void js_shell_native_execute_by_token_name(char out[31]) {
    js_shell_native_execute_name(out);
    memcpy(out + 23u, "By", 2u);
    memcpy(out + 25u, "Token", 6u);
}

static void js_shell_native_execute_void_name(char out[28]) {
    js_shell_native_execute_name(out);
    memcpy(out + 23u, "Void", 5u);
}

static void js_shell_native_execute_int_void_name(char out[31]) {
    js_shell_native_execute_name(out);
    memcpy(out + 23u, "Int", 3u);
    memcpy(out + 26u, "Void", 5u);
}

static char *js_shell_default_helper_owner(void) {
    const char *parts[] = { "io/github/hht0rro/", "javashroud/transforms/", "protection/Jni", "MicrokernelHelper" };
    size_t total = 0;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) total += strlen(parts[i]);
    char *out = (char *)malloc(total + 1u);
    if (!out) return 0;
    size_t offset = 0;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        size_t len = strlen(parts[i]);
        memcpy(out + offset, parts[i], len);
        offset += len;
    }
    out[offset] = 0;
    return out;
}

static char *js_shell_system_property(JNIEnv *env, const char *name) {
    if (!env || !name) return 0;
    jclass system_cls = (*env)->FindClass(env, "java/lang/System");
    if ((*env)->ExceptionCheck(env) || !system_cls) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0; }
    jmethodID get_property = (*env)->GetStaticMethodID(env, system_cls, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    if ((*env)->ExceptionCheck(env) || !get_property) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0; }
    jstring key = (*env)->NewStringUTF(env, name);
    if (!key) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0; }
    jstring value = (jstring)(*env)->CallStaticObjectMethod(env, system_cls, get_property, key);
    (*env)->DeleteLocalRef(env, key);
    if ((*env)->ExceptionCheck(env) || !value) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0; }
    const char *chars = (*env)->GetStringUTFChars(env, value, 0);
    char *out = chars ? js_shell_strdup(chars) : 0;
    if (chars) (*env)->ReleaseStringUTFChars(env, value, chars);
    (*env)->DeleteLocalRef(env, value);
    return out;
}

static char *js_shell_lookup_bound_method(JNIEnv *env, const char *owner, const char *name, const char *sig) {
    if (!env || !owner || !name || !sig) return 0;
    unsigned long long hash = 0xcbf29ce484222325ULL;
    hash = js_shell_fnv1a64(owner, hash);
    hash ^= (unsigned long long)'#'; hash *= 0x100000001b3ULL;
    hash = js_shell_fnv1a64(name, hash);
    hash ^= (unsigned long long)'#'; hash *= 0x100000001b3ULL;
    hash = js_shell_fnv1a64(sig, hash);
    char key[17];
    snprintf(key, sizeof(key), "%016llx", hash);
    char *bindings = js_shell_system_property(env, "j.m");
    if (!bindings) return 0;
    size_t key_len = strlen(key);
    char *cursor = bindings;
    while (*cursor) {
        char *line = cursor;
        char *eol = strchr(cursor, '\n');
        if (eol) *eol = 0;
        size_t line_len = strlen(line);
        while (line_len > 0 && (line[line_len - 1] == '\r' || line[line_len - 1] == ' ' || line[line_len - 1] == '\t')) line[--line_len] = 0;
        if (line_len > key_len + 1u && !strncmp(line, key, key_len) && line[key_len] == '=') {
            char *mapped = js_shell_strdup(line + key_len + 1u);
            free(bindings);
            return mapped;
        }
        if (!eol) break;
        cursor = eol + 1;
    }
    free(bindings);
    return 0;
}

static int js_shell_register_outer_shim(JNIEnv *env);

static jclass js_shell_find_helper_class(JNIEnv *env, char **owner_out) {
    char *owner = js_shell_system_property(env, "j.l");
    if (!owner || !owner[0]) {
        free(owner);
        owner = js_shell_default_helper_owner();
    }
    if (!owner) return 0;
    jclass cls = (*env)->FindClass(env, owner);
    if ((*env)->ExceptionCheck(env) || !cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        free(owner);
        return 0;
    }
    if (owner_out) *owner_out = owner; else free(owner);
    return cls;
}

static jint JNICALL js_shell_native_init(JNIEnv *env, jclass cls, jstring platform) {
    if (!g_inner_image.jni_on_load || !g_shell_vm || g_shell_failed) return JNI_ERR;
    if (!g_inner_onload_done) {
        jint loaded = g_inner_image.jni_on_load(g_shell_vm, JS_SHELL_MANUAL_MAP_RESERVED);
        if ((*env)->ExceptionCheck(env)) return JNI_ERR;
        if (loaded == JNI_ERR || loaded == 0) { g_shell_failed = 1; return JNI_ERR; }
        if (!g_inner_image.native_abi_table_v1) { g_shell_failed = 1; return JNI_ERR; }
        g_inner_abi = g_inner_image.native_abi_table_v1();
        if (!g_inner_abi || g_inner_abi->version != JS_NATIVE_ABI_TABLE_VERSION || !g_inner_abi->native_init || !g_inner_abi->native_verify || !g_inner_abi->native_heartbeat || !g_inner_abi->native_decrypt_aes || !g_inner_abi->native_get_version || !g_inner_abi->native_get_boot_token || !g_inner_abi->native_install_runtime_resource_key || !g_inner_abi->native_preload_runtime_resources || !g_inner_abi->native_derive_class_encryption_key || !g_inner_abi->execute_vm_resource || !g_inner_abi->execute_vm_resource_by_token || !g_inner_abi->execute_vm_resource_void || !g_inner_abi->execute_vm_resource_int_void) {
            g_shell_failed = 1;
            return JNI_ERR;
        }
        if (!js_shell_register_outer_shim(env)) {
            g_shell_failed = 1;
            return JNI_ERR;
        }
        g_inner_onload_done = 1;
        g_shell_loaded = 1;
        return 2;
    }
    return g_inner_abi && g_inner_abi->native_init ? g_inner_abi->native_init(env, cls, platform) : JNI_ERR;
}

static jint JNICALL js_shell_native_verify(JNIEnv *env, jclass cls, jbyteArray data, jbyteArray expected_mac) {
    if (!g_inner_abi || !g_inner_abi->native_verify) return 0;
    return g_inner_abi->native_verify(env, cls, data, expected_mac);
}

static jint JNICALL js_shell_native_heartbeat(JNIEnv *env, jclass cls) {
    if (!g_inner_abi || !g_inner_abi->native_heartbeat) return 0;
    return g_inner_abi->native_heartbeat(env, cls);
}

static jbyteArray JNICALL js_shell_native_decrypt_aes(JNIEnv *env, jclass cls, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr) {
    if (!g_inner_abi || !g_inner_abi->native_decrypt_aes) return 0;
    return g_inner_abi->native_decrypt_aes(env, cls, encrypted, keyArr, ivArr);
}

static jstring JNICALL js_shell_native_get_version(JNIEnv *env, jclass cls) {
    if (!g_inner_abi || !g_inner_abi->native_get_version) return 0;
    return g_inner_abi->native_get_version(env, cls);
}

static jlong JNICALL js_shell_native_get_boot_token(JNIEnv *env, jclass cls) {
    if (!g_inner_abi || !g_inner_abi->native_get_boot_token) return 0;
    return g_inner_abi->native_get_boot_token(env, cls);
}

static void JNICALL js_shell_native_install_runtime_resource_key(JNIEnv *env, jclass cls, jbyteArray keyArr) {
    if (!g_inner_abi || !g_inner_abi->native_install_runtime_resource_key) return;
    g_inner_abi->native_install_runtime_resource_key(env, cls, keyArr);
}

static void JNICALL js_shell_native_preload_runtime_resources(JNIEnv *env, jclass cls) {
    if (!g_inner_abi || !g_inner_abi->native_preload_runtime_resources) return;
    g_inner_abi->native_preload_runtime_resources(env, cls);
}

static jbyteArray JNICALL js_shell_native_derive_class_encryption_key(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length) {
    if (!g_inner_abi || !g_inner_abi->native_derive_class_encryption_key) return 0;
    return g_inner_abi->native_derive_class_encryption_key(env, cls, keyIdArr, saltArr, length);
}

static jobject JNICALL js_shell_execute_vm_resource(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args) {
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource) return 0;
    return g_inner_abi->execute_vm_resource(env, cls, entryToken, resourcePath, args);
}

static jobject JNICALL js_shell_execute_vm_resource_by_token(JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args) {
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_by_token) return 0;
    return g_inner_abi->execute_vm_resource_by_token(env, cls, entryToken, args);
}

static void JNICALL js_shell_execute_vm_resource_void(JNIEnv *env, jclass cls, jlong entryToken) {
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_void) return;
    g_inner_abi->execute_vm_resource_void(env, cls, entryToken);
}

static void JNICALL js_shell_execute_vm_resource_int_void(JNIEnv *env, jclass cls, jlong entryToken, jint arg0) {
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_int_void) return;
    g_inner_abi->execute_vm_resource_int_void(env, cls, entryToken, arg0);
}

static int js_shell_register_outer_shim(JNIEnv *env) {
    char *owner = 0;
    jclass helper_cls = js_shell_find_helper_class(env, &owner);
    if (!helper_cls || !owner) return 0;
    char native_init_name[11];
    char native_verify_name[13];
    char native_heartbeat_name[16];
    char native_version_name[17];
    char native_boot_token_name[19];
    char native_runtime_key_name[32];
    char native_preload_name[30];
    char native_decrypt_aes_name[17];
    char native_class_key_name[31];
    char native_exec_name[24];
    char native_exec_token_name[31];
    char native_void_name[28];
    char native_int_void_name[31];
    js_shell_native_init_name(native_init_name);
    js_shell_native_verify_name(native_verify_name);
    js_shell_native_heartbeat_name(native_heartbeat_name);
    js_shell_native_version_name(native_version_name);
    js_shell_native_boot_token_name(native_boot_token_name);
    js_shell_native_runtime_key_name(native_runtime_key_name);
    js_shell_native_preload_name(native_preload_name);
    js_shell_native_decrypt_aes_name(native_decrypt_aes_name);
    js_shell_native_class_key_name(native_class_key_name);
    js_shell_native_execute_name(native_exec_name);
    js_shell_native_execute_by_token_name(native_exec_token_name);
    js_shell_native_execute_void_name(native_void_name);
    js_shell_native_execute_int_void_name(native_int_void_name);
    char *original_owner = js_shell_default_helper_owner();
    char *mapped_init = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_init_name, "(Ljava/lang/String;)I") : 0;
    char *mapped_verify = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_verify_name, "([B[B)I") : 0;
    char *mapped_heartbeat = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_heartbeat_name, "()I") : 0;
    char *mapped_version = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_version_name, "()Ljava/lang/String;") : 0;
    char *mapped_boot_token = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_boot_token_name, "()J") : 0;
    char *mapped_runtime_key = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_runtime_key_name, "([B)V") : 0;
    char *mapped_preload = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_preload_name, "()V") : 0;
    char *mapped_decrypt_aes = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_decrypt_aes_name, "([B[B[B)[B") : 0;
    char *mapped_class_key = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_class_key_name, "([B[BI)[B") : 0;
    char *mapped_exec = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_exec_name, "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;") : 0;
    char *mapped_exec_token = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_exec_token_name, "(J[Ljava/lang/Object;)Ljava/lang/Object;") : 0;
    char *mapped_void = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_void_name, "(J)V") : 0;
    char *mapped_int_void = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_void_name, "(JI)V") : 0;
    JNINativeMethod methods[13];
    memset(methods, 0, sizeof(methods));
    methods[0].name = (char *)((mapped_init && mapped_init[0]) ? mapped_init : native_init_name);
    methods[0].signature = "(Ljava/lang/String;)I";
    methods[0].fnPtr = (void *)js_shell_native_init;
    methods[1].name = (char *)((mapped_verify && mapped_verify[0]) ? mapped_verify : native_verify_name);
    methods[1].signature = "([B[B)I";
    methods[1].fnPtr = (void *)js_shell_native_verify;
    methods[2].name = (char *)((mapped_heartbeat && mapped_heartbeat[0]) ? mapped_heartbeat : native_heartbeat_name);
    methods[2].signature = "()I";
    methods[2].fnPtr = (void *)js_shell_native_heartbeat;
    methods[3].name = (char *)((mapped_version && mapped_version[0]) ? mapped_version : native_version_name);
    methods[3].signature = "()Ljava/lang/String;";
    methods[3].fnPtr = (void *)js_shell_native_get_version;
    methods[4].name = (char *)((mapped_boot_token && mapped_boot_token[0]) ? mapped_boot_token : native_boot_token_name);
    methods[4].signature = "()J";
    methods[4].fnPtr = (void *)js_shell_native_get_boot_token;
    methods[5].name = (char *)((mapped_runtime_key && mapped_runtime_key[0]) ? mapped_runtime_key : native_runtime_key_name);
    methods[5].signature = "([B)V";
    methods[5].fnPtr = (void *)js_shell_native_install_runtime_resource_key;
    methods[6].name = (char *)((mapped_preload && mapped_preload[0]) ? mapped_preload : native_preload_name);
    methods[6].signature = "()V";
    methods[6].fnPtr = (void *)js_shell_native_preload_runtime_resources;
    methods[7].name = (char *)((mapped_decrypt_aes && mapped_decrypt_aes[0]) ? mapped_decrypt_aes : native_decrypt_aes_name);
    methods[7].signature = "([B[B[B)[B";
    methods[7].fnPtr = (void *)js_shell_native_decrypt_aes;
    methods[8].name = (char *)((mapped_class_key && mapped_class_key[0]) ? mapped_class_key : native_class_key_name);
    methods[8].signature = "([B[BI)[B";
    methods[8].fnPtr = (void *)js_shell_native_derive_class_encryption_key;
    methods[9].name = (char *)((mapped_exec && mapped_exec[0]) ? mapped_exec : native_exec_name);
    methods[9].signature = "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[9].fnPtr = (void *)js_shell_execute_vm_resource;
    methods[10].name = (char *)((mapped_exec_token && mapped_exec_token[0]) ? mapped_exec_token : native_exec_token_name);
    methods[10].signature = "(J[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[10].fnPtr = (void *)js_shell_execute_vm_resource_by_token;
    methods[11].name = (char *)((mapped_void && mapped_void[0]) ? mapped_void : native_void_name);
    methods[11].signature = "(J)V";
    methods[11].fnPtr = (void *)js_shell_execute_vm_resource_void;
    methods[12].name = (char *)((mapped_int_void && mapped_int_void[0]) ? mapped_int_void : native_int_void_name);
    methods[12].signature = "(JI)V";
    methods[12].fnPtr = (void *)js_shell_execute_vm_resource_int_void;
    int ok = ((*env)->RegisterNatives(env, helper_cls, methods, (jint)(sizeof(methods) / sizeof(methods[0]))) == 0);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); ok = 0; }
    free(mapped_init);
    free(mapped_verify);
    free(mapped_heartbeat);
    free(mapped_version);
    free(mapped_boot_token);
    free(mapped_runtime_key);
    free(mapped_preload);
    free(mapped_decrypt_aes);
    free(mapped_class_key);
    free(mapped_exec);
    free(mapped_exec_token);
    free(mapped_void);
    free(mapped_int_void);
    free(original_owner);
    free(owner);
    return ok;
}

jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    js_shell_payload_meta meta;
    unsigned char *stored = 0;
    unsigned char *decoded = 0;
    js_shell_payload_view view;
    memset(&view, 0, sizeof(view));
    memset(&meta, 0, sizeof(meta));

    if (!js_shell_verify_payload(&meta)) {
        return js_shell_fail_onload();
    }

    stored = js_shell_alloc((size_t)JS_SHELL_PAYLOAD_SIZE);
    if (!stored) {
        return js_shell_fail_onload();
    }
    memcpy(stored, js_shell_payload_bytes, (size_t)JS_SHELL_PAYLOAD_SIZE);
    if (!js_shell_decode_payload_chunks(stored, (size_t)JS_SHELL_PAYLOAD_SIZE, js_shell_stream_key, sizeof(js_shell_stream_key), meta.nonce, meta.layout_profile, meta.dispatcher_profile, meta.chunk_size, meta.chunk_tags, meta.chunk_tags_size)) {
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        return js_shell_fail_onload();
    }
    if (meta.compression_codec == JS_SHELL_COMPRESSION_NONE) {
        if (meta.stored_size != meta.original_size || meta.stored_size != JS_SHELL_PAYLOAD_SIZE) {
            js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
            return js_shell_fail_onload();
        }
        decoded = stored;
        stored = 0;
    } else if (meta.compression_codec == JS_SHELL_COMPRESSION_ZSTD) {
        decoded = js_shell_alloc((size_t)meta.original_size);
        if (!decoded) {
            js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
            return js_shell_fail_onload();
        }
        size_t written = ZSTD_decompress(decoded, (size_t)meta.original_size, stored, (size_t)meta.stored_size);
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        stored = 0;
        if (ZSTD_isError(written) || written != (size_t)meta.original_size) {
            js_shell_wipe_free(decoded, (size_t)meta.original_size);
            return js_shell_fail_onload();
        }
    } else {
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        return js_shell_fail_onload();
    }

    view.header = js_shell_payload_header;
    view.header_size = JS_SHELL_PAYLOAD_HEADER_SIZE;
    view.payload = js_shell_payload_bytes;
    view.payload_size = JS_SHELL_PAYLOAD_SIZE;
    view.decoded_payload = decoded;
    view.decoded_payload_size = (size_t)meta.original_size;
    view.mac = js_shell_payload_mac;
    view.mac_size = sizeof(js_shell_payload_mac);
    view.binding_tag = js_shell_binding_tag;
    view.binding_tag_size = sizeof(js_shell_binding_tag);
    view.layout_profile = meta.layout_profile;
    view.dispatcher_profile = meta.dispatcher_profile;

    if (!js_shell_load_inner_image(&view, &g_inner_image) || !g_inner_image.jni_on_load) {
        js_shell_wipe_free(decoded, (size_t)meta.original_size);
        return js_shell_fail_onload();
    }
    js_shell_wipe_free(decoded, (size_t)meta.original_size);
    g_shell_vm = vm;
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env || !js_shell_register_outer_shim(env)) {
        return js_shell_fail_onload();
    }
    return JNI_VERSION_1_6;
}

void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
#if defined(_WIN32)
    /* Windows manual-mapped PE images are process-lifetime. Calling the inner
     * JNI_OnUnload, TLS detach, or DllMain detach from the outer library unload
     * path can re-enter JVM/CRT teardown through an image the OS loader never
     * registered. Let process exit reclaim the mapped image instead. */
    (void)vm;
    (void)reserved;
    return;
#else
    if (g_shell_loaded && g_inner_image.jni_on_unload) {
        g_inner_image.jni_on_unload(vm, reserved);
    }
    js_shell_unload_inner_image(&g_inner_image);
    memset(&g_inner_image, 0, sizeof(g_inner_image));
    g_shell_loaded = 0;
    (void)vm;
    (void)reserved;
#endif
}
