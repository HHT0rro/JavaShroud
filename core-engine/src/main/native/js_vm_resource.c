#include "js_vm_resource.h"
#include "js_crypto.h"
#include "js_jni_runtime.h"
#include "js_vm_core.h"
#include "js_vm_symbol.h"
#include "zstd.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#define JS_VM_CALL_GATE_SIZE 8192

typedef struct {
    char original[JS_VM_CALL_GATE_KEY_LEN];
    char sealed[JS_VM_CALL_GATE_KEY_LEN];
    int active;
} js_vm_resource_alias_entry;

static js_vm_call_gate_entry js_vm_call_gate[JS_VM_CALL_GATE_SIZE];
static js_vm_resource_alias_entry js_vm_resource_aliases[JS_VM_CALL_GATE_SIZE];
static int js_vm_call_gate_count = 0;
static js_vm_ephemeral_cache_entry *js_vm_ephemeral_cache = NULL;
#ifdef _WIN32
static CRITICAL_SECTION js_vm_cache_lock;
static volatile LONG js_vm_cache_lock_ready = 0;
#else
static pthread_mutex_t js_vm_cache_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
JS_HIDDEN volatile int js_vm_preload_in_progress = 0;

JS_HIDDEN char js_vm_last_prepare_stage[96] = {0};

static void js_vm_set_prepare_stage(const char *s) {
    if (!s) { js_vm_last_prepare_stage[0] = 0; return; }
    size_t n = strlen(s);
    if (n >= sizeof(js_vm_last_prepare_stage)) n = sizeof(js_vm_last_prepare_stage) - 1;
    memcpy(js_vm_last_prepare_stage, s, n);
    js_vm_last_prepare_stage[n] = 0;
}

JS_HIDDEN unsigned char* js_vbc4_zstd_decompress_owned(const unsigned char *stored, uint32_t stored_len, uint32_t plain_len) {
    if (!stored || stored_len == 0) return NULL;
    if (stored_len == plain_len) {
        unsigned char *plain_copy = (unsigned char*)malloc((size_t)plain_len);
        if (!plain_copy) return NULL;
        memcpy(plain_copy, stored, (size_t)plain_len);
        return plain_copy;
    }
    unsigned char *plain = plain_len == 0 ? (unsigned char*)calloc(1, 1) : (unsigned char*)malloc((size_t)plain_len);
    if (!plain) return NULL;
    size_t written = ZSTD_decompress(plain, (size_t)plain_len, stored, (size_t)stored_len);
    if (ZSTD_isError(written) || written != (size_t)plain_len) {
        js_vbc4_wipe_volatile(plain, (size_t)plain_len);
        free(plain);
        return NULL;
    }
    return plain;
}

static void js_vm_cache_lock_enter(void) {
#ifdef _WIN32
    if (js_vm_cache_lock_ready) EnterCriticalSection(&js_vm_cache_lock);
#else
    pthread_mutex_lock(&js_vm_cache_lock);
#endif
}

static void js_vm_cache_lock_leave(void) {
#ifdef _WIN32
    if (js_vm_cache_lock_ready) LeaveCriticalSection(&js_vm_cache_lock);
#else
    pthread_mutex_unlock(&js_vm_cache_lock);
#endif
}

JS_HIDDEN void js_vm_cache_lock_init(void) {
#ifdef _WIN32
    if (!js_vm_cache_lock_ready) {
        InitializeCriticalSection(&js_vm_cache_lock);
        js_vm_cache_lock_ready = 1;
    }
#endif
}

JS_HIDDEN void js_vm_cache_lock_destroy(void) {
#ifdef _WIN32
    if (js_vm_cache_lock_ready) {
        DeleteCriticalSection(&js_vm_cache_lock);
        js_vm_cache_lock_ready = 0;
    }
#endif
}

JS_HIDDEN void js_vm_resource_alias_register(const char *original_path, const char *sealed_path) {
    if (!original_path || !sealed_path || !original_path[0] || !sealed_path[0] || strcmp(original_path, sealed_path) == 0) return;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        if (js_vm_resource_aliases[i].active && strcmp(js_vm_resource_aliases[i].original, original_path) == 0) {
            strncpy(js_vm_resource_aliases[i].sealed, sealed_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            js_vm_resource_aliases[i].sealed[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            return;
        }
    }
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        if (!js_vm_resource_aliases[i].active) {
            js_vm_resource_aliases[i].active = 1;
            strncpy(js_vm_resource_aliases[i].original, original_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            strncpy(js_vm_resource_aliases[i].sealed, sealed_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            js_vm_resource_aliases[i].original[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            js_vm_resource_aliases[i].sealed[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            return;
        }
    }
}

JS_HIDDEN const char* js_vm_resource_alias_resolve(const char *path) {
    if (!path || !path[0]) return path;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        if (js_vm_resource_aliases[i].active && strcmp(js_vm_resource_aliases[i].original, path) == 0) return js_vm_resource_aliases[i].sealed;
    }
    return path;
}

static uint32_t js_vm_call_gate_hash_token(jlong token) {
    uint64_t x = (uint64_t)token;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)(x ^ (x >> 32));
}

JS_HIDDEN void js_vm_call_gate_register(jlong entry_token, const char *resource_path) {
    if (entry_token == 0 || !resource_path) return;
    if (js_vm_call_gate_count >= JS_VM_CALL_GATE_SIZE - 1) return;
    uint32_t h = js_vm_call_gate_hash_token(entry_token) % JS_VM_CALL_GATE_SIZE;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        int idx = (int)((h + (uint32_t)i) % JS_VM_CALL_GATE_SIZE);
        if (!js_vm_call_gate[idx].active) {
            js_vm_call_gate[idx].entry_token = entry_token;
            strncpy(js_vm_call_gate[idx].resource_path, resource_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            js_vm_call_gate[idx].resource_path[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            js_vm_call_gate[idx].active = 1;
            js_vm_call_gate[idx].loading = 0;
            js_vm_call_gate_count++;
            return;
        }
        if (js_vm_call_gate[idx].entry_token == entry_token) return;
    }
}

JS_HIDDEN const js_vm_call_gate_entry* js_vm_call_gate_lookup(jlong entry_token) {
    if (entry_token == 0) return NULL;
    uint32_t h = js_vm_call_gate_hash_token(entry_token) % JS_VM_CALL_GATE_SIZE;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        int idx = (int)((h + (uint32_t)i) % JS_VM_CALL_GATE_SIZE);
        if (!js_vm_call_gate[idx].active) return NULL;
        if (js_vm_call_gate[idx].entry_token == entry_token) return &js_vm_call_gate[idx];
    }
    return NULL;
}

static js_vm_call_gate_entry* js_vm_call_gate_lookup_mutable(jlong entry_token) {
    if (entry_token == 0) return NULL;
    uint32_t h = js_vm_call_gate_hash_token(entry_token) % JS_VM_CALL_GATE_SIZE;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        int idx = (int)((h + (uint32_t)i) % JS_VM_CALL_GATE_SIZE);
        if (!js_vm_call_gate[idx].active) return NULL;
        if (js_vm_call_gate[idx].entry_token == entry_token) return &js_vm_call_gate[idx];
    }
    return NULL;
}

JS_HIDDEN int js_vm_call_gate_mark_loading(jlong entry_token, const char *resource_path) {
    js_vm_call_gate_entry *entry = js_vm_call_gate_lookup_mutable(entry_token);
    if (!entry || !resource_path || strcmp(entry->resource_path, resource_path) != 0 || entry->loading) return 0;
    entry->loading = 1;
    return 1;
}

JS_HIDDEN void js_vm_call_gate_clear_loading(jlong entry_token) {
    js_vm_call_gate_entry *entry = js_vm_call_gate_lookup_mutable(entry_token);
    if (entry) entry->loading = 0;
}

JS_HIDDEN void js_vm_call_gate_reset(void) {
    js_vbc4_wipe_volatile(js_vm_call_gate, sizeof(js_vm_call_gate));
    js_vbc4_wipe_volatile(js_vm_resource_aliases, sizeof(js_vm_resource_aliases));
    js_vm_call_gate_count = 0;
}

static int js_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

JS_HIDDEN int js_hex32_to_bytes(const char *hex, unsigned char out[32]) {
    if (!hex || !out) return 0;
    for (int i = 0; i < 32; i++) {
        int hi = js_hex_nibble(hex[i * 2]);
        int lo = js_hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return hex[64] == 0 || hex[64] == '|';
}

JS_HIDDEN int js_parse_u32_token(const char *text, uint32_t *out) {
    if (!text || !text[0] || !out) return 0;
    uint64_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10u + (uint64_t)(*p - '0');
        if (value > 0xFFFFFFFFULL) return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

JS_HIDDEN char* js_next_manifest_field(char **cursor) {
    if (!cursor || !*cursor) return NULL;
    char *start = *cursor;
    char *sep = strchr(start, '|');
    if (sep) {
        *sep = 0;
        *cursor = sep + 1;
    } else {
        char *end = start + strlen(start);
        while (end > start && (end[-1] == '\n' || end[-1] == '\r')) *--end = 0;
        *cursor = NULL;
    }
    return start;
}

static void js_vm_resource_clear_exception(JNIEnv *env) {
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

JS_HIDDEN jobject js_vm_class_resource_as_stream(JNIEnv *env, jobject class_obj, jstring resource_path) {
    if (!class_obj || !resource_path || !js_jni_cache.initialized) return NULL;
    jobject loader = (*env)->CallObjectMethod(env, class_obj, js_jni_cache.class_get_class_loader);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return NULL; }
    const char *raw_path = j2c(env, resource_path);
    if (!raw_path) { js_vm_resource_clear_exception(env); return NULL; }
    char *resolved = NULL;
    if (raw_path[0] == '/') {
        resolved = js_strdup(raw_path + 1);
    } else {
        jstring class_name_j = (jstring)(*env)->CallObjectMethod(env, class_obj, js_jni_cache.class_get_name);
        if ((*env)->ExceptionCheck(env) || !class_name_j) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        } else {
            const char *class_name = j2c(env, class_name_j);
            if (class_name) {
                const char *last_dot = strrchr(class_name, '.');
                size_t package_len = last_dot ? (size_t)(last_dot - class_name) : 0;
                size_t path_len = strlen(raw_path);
                resolved = (char*)malloc(package_len + (package_len ? 1 : 0) + path_len + 1);
                if (resolved) {
                    size_t pos = 0;
                    for (size_t i = 0; i < package_len; i++) resolved[pos++] = class_name[i] == '.' ? '/' : class_name[i];
                    if (package_len) resolved[pos++] = '/';
                    memcpy(resolved + pos, raw_path, path_len + 1);
                }
                rls(env, class_name_j, class_name);
            }
            (*env)->DeleteLocalRef(env, class_name_j);
        }
    }
    rls(env, resource_path, raw_path);
    if (!resolved) return NULL;
    jstring resolved_j = (*env)->NewStringUTF(env, resolved);
    free(resolved);
    if (!resolved_j) { js_vm_resource_clear_exception(env); return NULL; }
    jobject stream = loader ? js_vm_resource_from_loader(env, loader, resolved_j) : NULL;
    (*env)->DeleteLocalRef(env, resolved_j);
    if (stream) return stream;
    return (*env)->CallObjectMethod(env, class_obj, js_jni_cache.class_get_resource_as_stream, resource_path);
}

JS_HIDDEN jobject js_vm_resource_from_loader(JNIEnv *env, jobject loader, jstring resourcePath) {
    if (!loader || !resourcePath) return NULL;
    jclass loader_cls = js_jni_cache.initialized ? js_jni_cache.class_loader_class : (*env)->FindClass(env, "java/lang/ClassLoader");
    if (!loader_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID get_resource = js_jni_cache.initialized ? js_jni_cache.class_loader_get_resource_as_stream : (*env)->GetMethodID(env, loader_cls, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    if (!get_resource) { js_vm_resource_clear_exception(env); return NULL; }
    jobject stream = (*env)->CallObjectMethod(env, loader, get_resource, resourcePath);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return NULL; }
    return stream;
}

JS_HIDDEN jobject js_vm_context_class_loader(JNIEnv *env) {
    jclass thread_cls = js_jni_cache.initialized ? js_jni_cache.thread_class : (*env)->FindClass(env, "java/lang/Thread");
    if (!thread_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID current_thread = js_jni_cache.initialized ? js_jni_cache.thread_current_thread : (*env)->GetStaticMethodID(env, thread_cls, "currentThread", "()Ljava/lang/Thread;");
    jmethodID get_context_loader = js_jni_cache.initialized ? js_jni_cache.thread_get_context_class_loader : (*env)->GetMethodID(env, thread_cls, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (!current_thread || !get_context_loader) { js_vm_resource_clear_exception(env); return NULL; }
    jobject thread = (*env)->CallStaticObjectMethod(env, thread_cls, current_thread);
    if ((*env)->ExceptionCheck(env) || !thread) { js_vm_resource_clear_exception(env); return NULL; }
    jobject loader = (*env)->CallObjectMethod(env, thread, get_context_loader);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return NULL; }
    return loader;
}

JS_HIDDEN jobject js_vm_helper_class_loader(JNIEnv *env, jclass helper_cls) {
    if (!helper_cls) return NULL;
    jclass class_cls = js_jni_cache.initialized ? js_jni_cache.class_class : (*env)->FindClass(env, "java/lang/Class");
    if (!class_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID get_class_loader = js_jni_cache.initialized ? js_jni_cache.class_get_class_loader : (*env)->GetMethodID(env, class_cls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_class_loader) { js_vm_resource_clear_exception(env); return NULL; }
    jobject loader = (*env)->CallObjectMethod(env, helper_cls, get_class_loader);
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    return loader;
}

static jobject js_vm_resource_from_helper_class(JNIEnv *env, jclass helper_cls, jstring resourcePath) {
    if (!helper_cls || !resourcePath) return NULL;
    const char *path = j2c(env, resourcePath);
    if (!path) { js_vm_resource_clear_exception(env); return NULL; }
    size_t len = strlen(path);
    char *absolute = (char*)malloc(len + 2);
    if (!absolute) { rls(env, resourcePath, path); return NULL; }
    absolute[0] = '/';
    memcpy(absolute + 1, path, len + 1);
    rls(env, resourcePath, path);
    jstring absolute_path = (*env)->NewStringUTF(env, absolute);
    free(absolute);
    if (!absolute_path) { js_vm_resource_clear_exception(env); return NULL; }

    jclass class_cls = js_jni_cache.initialized ? js_jni_cache.class_class : (*env)->FindClass(env, "java/lang/Class");
    if (!class_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID get_resource = js_jni_cache.initialized ? js_jni_cache.class_get_resource_as_stream : (*env)->GetMethodID(env, class_cls, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    if (!get_resource) { js_vm_resource_clear_exception(env); return NULL; }
    jobject stream = (*env)->CallObjectMethod(env, helper_cls, get_resource, absolute_path);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return NULL; }
    return stream;
}

static jbyteArray js_vm_read_stream_bytes(JNIEnv *env, jobject stream) {
    if (!stream) return NULL;
    jbyteArray bytes = NULL;
    jclass stream_cls = js_jni_cache.initialized ? js_jni_cache.input_stream_class : (*env)->FindClass(env, "java/io/InputStream");
    if (stream_cls) {
        jmethodID read_all = js_jni_cache.initialized ? js_jni_cache.input_stream_read_all_bytes : (*env)->GetMethodID(env, stream_cls, "readAllBytes", "()[B");
        jmethodID close = js_jni_cache.initialized ? js_jni_cache.input_stream_close : (*env)->GetMethodID(env, stream_cls, "close", "()V");
        if (read_all) bytes = (jbyteArray)(*env)->CallObjectMethod(env, stream, read_all);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); bytes = NULL; }
        if (close) (*env)->CallVoidMethod(env, stream, close);
        js_vm_resource_clear_exception(env);
    } else {
        js_vm_resource_clear_exception(env);
    }
    return bytes;
}

JS_HIDDEN js_vm_loaded_resource js_vm_load_resource_bytes_with_loader(JNIEnv *env, jclass helper_cls, jstring resourcePath) {
    js_vm_loaded_resource result;
    memset(&result, 0, sizeof(result));
    if (!resourcePath) return result;
    jobject loader = js_vm_context_class_loader(env);
    jobject stream = js_vm_resource_from_loader(env, loader, resourcePath);
    if (!stream) {
        loader = js_vm_helper_class_loader(env, helper_cls);
        stream = js_vm_resource_from_loader(env, loader, resourcePath);
    }
    if (!stream) {
        loader = NULL;
        stream = js_vm_resource_from_helper_class(env, helper_cls, resourcePath);
    }
    result.bytes = js_vm_read_stream_bytes(env, stream);
    result.loader = result.bytes && loader ? loader : NULL;
    return result;
}

JS_HIDDEN jbyteArray js_vm_load_resource_bytes(JNIEnv *env, jclass helper_cls, jstring resourcePath) {
    js_vm_loaded_resource loaded = js_vm_load_resource_bytes_with_loader(env, helper_cls, resourcePath);
    return loaded.bytes;
}

JS_HIDDEN unsigned char* js_vm_decode_resource_path_owned(JNIEnv *env, jclass helper_cls, const char *path, int *out_len) {
    if (!path || !path[0] || !out_len) return NULL;
    const char *load_path = js_vm_resource_alias_resolve(path);
    jstring path_j = (*env)->NewStringUTF(env, load_path);
    if (!path_j) { js_clear_pending_exception(env); return NULL; }
    js_vm_loaded_resource loaded = js_vm_load_resource_bytes_with_loader(env, helper_cls, path_j);
    (*env)->DeleteLocalRef(env, path_j);
    if (!loaded.bytes) return NULL;
    int raw_len = (*env)->GetArrayLength(env, loaded.bytes);
    jbyte *raw_bytes = raw_len > 0 ? (*env)->GetByteArrayElements(env, loaded.bytes, NULL) : NULL;
    unsigned char *decoded = NULL;
    if (raw_bytes) {
        decoded = js_runtime_resource_decode_owned((const unsigned char*)raw_bytes, raw_len, out_len);
        js_vbc4_wipe_volatile(raw_bytes, (size_t)raw_len);
        (*env)->ReleaseByteArrayElements(env, loaded.bytes, raw_bytes, JNI_ABORT);
    }
    return decoded;
}

JS_HIDDEN unsigned char* js_vm_reassemble_sliced_resource(JNIEnv *env, jclass helper_cls, unsigned char *decoded, int decoded_len, int *out_len) {
    if (!decoded || decoded_len < 10 || !out_len || memcmp(decoded, "VBC4S|1|", 8) != 0) return decoded;
    char *manifest = (char*)calloc((size_t)decoded_len + 1u, 1u);
    if (!manifest) return NULL;
    memcpy(manifest, decoded, (size_t)decoded_len);
    js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
    free(decoded);
    decoded = NULL;

    char *line = manifest;
    char *next_line = strchr(line, '\n');
    if (!next_line) { js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL; }
    *next_line++ = 0;
    char *cursor = line;
    char *magic = js_next_manifest_field(&cursor);
    char *version = js_next_manifest_field(&cursor);
    char *total_text = js_next_manifest_field(&cursor);
    char *count_text = js_next_manifest_field(&cursor);
    uint32_t total_len = 0;
    uint32_t shard_count = 0;
    if (!magic || strcmp(magic, "VBC4S") != 0 || !version || strcmp(version, "1") != 0 ||
        !js_parse_u32_token(total_text, &total_len) || !js_parse_u32_token(count_text, &shard_count) ||
        total_len == 0 || shard_count < 2 || shard_count > 16 || total_len > 64u * 1024u * 1024u) {
        js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL;
    }
    unsigned char *assembled = (unsigned char*)calloc((size_t)total_len, 1u);
    unsigned char *seen = (unsigned char*)calloc((size_t)shard_count, 1u);
    if (!assembled || !seen) {
        if (assembled) free(assembled);
        if (seen) free(seen);
        js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL;
    }
    int ok = 1;
    uint32_t loaded_count = 0;
    line = next_line;
    while (line && *line && ok) {
        char *line_end = strchr(line, '\n');
        if (line_end) *line_end = 0;
        char *field_cursor = line;
        char *index_text = js_next_manifest_field(&field_cursor);
        char *offset_text = js_next_manifest_field(&field_cursor);
        char *length_text = js_next_manifest_field(&field_cursor);
        char *sha_text = js_next_manifest_field(&field_cursor);
        char *path_text = js_next_manifest_field(&field_cursor);
        uint32_t index = 0, offset = 0, length = 0;
        unsigned char expected_sha[32];
        memset(expected_sha, 0, sizeof(expected_sha));
        if (!js_parse_u32_token(index_text, &index) || !js_parse_u32_token(offset_text, &offset) ||
            !js_parse_u32_token(length_text, &length) || index >= shard_count || seen[index] ||
            length == 0 || offset > total_len || length > total_len - offset || !sha_text || strlen(sha_text) != 64 ||
            !js_hex32_to_bytes(sha_text, expected_sha) || !path_text || !path_text[0]) {
            ok = 0;
        } else {
            int shard_len = 0;
            unsigned char *shard = js_vm_decode_resource_path_owned(env, helper_cls, path_text, &shard_len);
            if (!shard || shard_len != (int)length) {
                ok = 0;
            } else {
                unsigned char actual_sha[32];
                js_sha256_ctx sha_ctx;
                js_sha256_init(&sha_ctx);
                js_sha256_update(&sha_ctx, shard, shard_len);
                js_sha256_final(&sha_ctx, actual_sha);
                if (memcmp(actual_sha, expected_sha, 32) != 0) {
                    ok = 0;
                } else {
                    memcpy(assembled + offset, shard, (size_t)length);
                    seen[index] = 1;
                    loaded_count++;
                }
                js_vbc4_wipe_volatile(actual_sha, sizeof(actual_sha));
                js_vbc4_wipe_volatile(&sha_ctx, sizeof(sha_ctx));
            }
            js_vbc4_wipe_volatile(expected_sha, sizeof(expected_sha));
            if (shard) { js_vbc4_wipe_volatile(shard, (size_t)(shard_len > 0 ? shard_len : 0)); free(shard); }
        }
        line = line_end ? line_end + 1 : NULL;
    }
    for (uint32_t i = 0; ok && i < shard_count; i++) if (!seen[i]) ok = 0;
    if (loaded_count != shard_count) ok = 0;
    js_vbc4_wipe_volatile(seen, (size_t)shard_count);
    free(seen);
    js_vbc4_wipe_volatile(manifest, (size_t)decoded_len);
    free(manifest);
    if (!ok) {
        js_vbc4_wipe_volatile(assembled, (size_t)total_len);
        free(assembled);
        return NULL;
    }
    *out_len = (int)total_len;
    return assembled;
}

JS_HIDDEN void js_vm_register_preload_index_entries(const unsigned char *index_bytes, int index_len) {
    if (!index_bytes || index_len <= 0) return;
    int line_start = 0;
    for (int i = 0; i <= index_len; i++) {
        if (i != index_len && index_bytes[i] != '\n' && index_bytes[i] != '\r') continue;
        int line_end = i;
        while (line_start < line_end && (index_bytes[line_start] == ' ' || index_bytes[line_start] == '\t')) line_start++;
        while (line_end > line_start && (index_bytes[line_end - 1] == ' ' || index_bytes[line_end - 1] == '\t')) line_end--;
        if (line_end > line_start) {
            int sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1, sep5 = -1;
            for (int p = line_start; p < line_end; p++) {
                if (index_bytes[p] != '|') continue;
                if (sep1 < 0) sep1 = p;
                else if (sep2 < 0) sep2 = p;
                else if (sep3 < 0) sep3 = p;
                else if (sep4 < 0) sep4 = p;
                else { sep5 = p; break; }
            }
            if (sep1 == line_start + 1 && index_bytes[line_start] == 'A' && sep2 > sep1 + 1 && sep2 + 1 < line_end) {
                char *original_path = js_substr_dup((const char*)index_bytes + sep1 + 1, (size_t)(sep2 - sep1 - 1));
                char *sealed_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(line_end - sep2 - 1));
                if (original_path && sealed_path) js_vm_resource_alias_register(original_path, sealed_path);
                if (original_path) { js_vbc4_wipe_volatile(original_path, strlen(original_path)); free(original_path); }
                if (sealed_path) { js_vbc4_wipe_volatile(sealed_path, strlen(sealed_path)); free(sealed_path); }
                while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
                line_start = i + 1;
                continue;
            }
            if (sep1 > line_start && sep1 + 1 < line_end && sep1 - line_start <= 16) {
                unsigned long long token = 0;
                int valid = 1;
                for (int p = line_start; p < sep1; p++) {
                    unsigned char ch = index_bytes[p];
                    int nibble = (ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' && ch <= 'f') ? (ch - 'a' + 10) : (ch >= 'A' && ch <= 'F') ? (ch - 'A' + 10) : -1;
                    if (nibble < 0) { valid = 0; break; }
                    token = (token << 4) | (unsigned long long)nibble;
                }
                int path_start = sep1 + 1;
                int path_end = sep2 > 0 ? sep2 : line_end;
                if (valid && path_end > path_start) {
                    char *resource_path = js_substr_dup((const char*)index_bytes + path_start, (size_t)(path_end - path_start));
                    if (resource_path) {
                        char *binding_resource_path = NULL;
                        if (sep4 > 0) {
                            int binding_resource_end = sep5 > 0 ? sep5 : line_end;
                            binding_resource_path = js_substr_dup((const char*)index_bytes + sep4 + 1, (size_t)(binding_resource_end - sep4 - 1));
                        }
                        const char *gate_path = binding_resource_path && binding_resource_path[0] ? binding_resource_path : resource_path;
                        js_vm_call_gate_register((jlong)token, gate_path);
                        if (binding_resource_path && strcmp(binding_resource_path, resource_path) != 0) js_vm_resource_alias_register(binding_resource_path, resource_path);
                        if (sep2 > 0 && sep3 > 0 && sep5 > 0) {
                            char *manifest_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(sep3 - sep2 - 1));
                            char *binding_manifest_path = js_substr_dup((const char*)index_bytes + sep5 + 1, (size_t)(line_end - sep5 - 1));
                            if (manifest_path && binding_manifest_path && strcmp(binding_manifest_path, manifest_path) != 0) js_vm_resource_alias_register(binding_manifest_path, manifest_path);
                            if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                            if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                        }
                        if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                        js_vbc4_wipe_volatile(resource_path, strlen(resource_path));
                        free(resource_path);
                    }
                }
            }
        }
        while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
        line_start = i + 1;
    }
}

JS_HIDDEN js_vm_program* js_vm_prepare_resource_program_bound(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, const char *binding_path_override) {
    if (!resourcePath || entry_token == 0) return NULL;
    const char *resource_path = j2c(env, resourcePath);
    if (!resource_path) {
        rls(env, resourcePath, resource_path);
        return NULL;
    }
    const char *load_resource_path = js_vm_resource_alias_resolve(resource_path);
    jstring loadResourcePath = resourcePath;
    if (load_resource_path && resource_path && strcmp(load_resource_path, resource_path) != 0) {
        loadResourcePath = (*env)->NewStringUTF(env, load_resource_path);
        if (!loadResourcePath) {
            js_vm_clear_exception(env);
            rls(env, resourcePath, resource_path);
            return NULL;
        }
    }
    js_vm_loaded_resource loaded = js_vm_load_resource_bytes_with_loader(env, resource_cls, loadResourcePath);
    if (loadResourcePath != resourcePath) (*env)->DeleteLocalRef(env, loadResourcePath);
    if (!loaded.bytes) {
        js_vm_set_prepare_stage("resource-load");
        rls(env, resourcePath, resource_path);
        return NULL;
    }
    int decoded_len = 0;
    unsigned char *decoded = NULL;
    int raw_len = (*env)->GetArrayLength(env, loaded.bytes);
    jbyte *raw_bytes = raw_len > 0 ? (*env)->GetByteArrayElements(env, loaded.bytes, NULL) : NULL;
    if (raw_bytes) {
        decoded = js_runtime_resource_decode_owned((const unsigned char*)raw_bytes, raw_len, &decoded_len);
        js_vbc4_wipe_volatile(raw_bytes, (size_t)raw_len);
        (*env)->ReleaseByteArrayElements(env, loaded.bytes, raw_bytes, JNI_ABORT);
    }
    if (!decoded) {
        js_vm_set_prepare_stage("decode");
        rls(env, resourcePath, resource_path);
        return NULL;
    }
    decoded = js_vm_reassemble_sliced_resource(env, resource_cls, decoded, decoded_len, &decoded_len);
    if (!decoded) {
        js_vm_set_prepare_stage("reassemble");
        rls(env, resourcePath, resource_path);
        return NULL;
    }
    js_vm_program *parsed_program = (js_vm_program*)calloc(1, sizeof(js_vm_program));
    if (!parsed_program) {
        js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
        free(decoded);
        rls(env, resourcePath, resource_path);
        return NULL;
    }
    unsigned char binding_buf[1200];
    const char *binding_resource_path = binding_path_override && binding_path_override[0] ? binding_path_override : (resource_path ? resource_path : "");
    int binding_len = js_vm_build_state_binding(entry_token, binding_resource_path, binding_buf, (int)sizeof(binding_buf));
    int parsed = binding_len > 0 ? js_vm_parse_program(decoded, decoded_len, parsed_program, binding_buf, binding_len) : 0;
    js_vbc4_wipe_volatile(binding_buf, sizeof(binding_buf));
    js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
    free(decoded);
    decoded = NULL;
    if (!parsed) {
        js_vm_set_prepare_stage("parse");
        js_vm_free_program(env, parsed_program);
        free(parsed_program);
        rls(env, resourcePath, resource_path);
        js_vm_fail_closed(env, NULL);
        return NULL;
    }
    parsed_program->entry_token = entry_token;
    js_vm_call_gate_register(entry_token, resource_path);
    parsed_program->return_desc = js_vm_return_descriptor_from_meta(parsed_program, entry_token);
    if (!parsed_program->return_desc) {
        js_vm_set_prepare_stage("return-desc");
        rls(env, resourcePath, resource_path);
        js_vm_free_program(env, parsed_program);
        free(parsed_program);
        return NULL;
    }
    rls(env, resourcePath, resource_path);
    return parsed_program;
}

JS_HIDDEN js_vm_program* js_vm_prepare_resource_program(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath) {
    return js_vm_prepare_resource_program_bound(env, resource_cls, entry_token, resourcePath, NULL);
}

JS_HIDDEN js_vm_program* js_vm_preload_indexed_program_on_demand(JNIEnv *env, jclass resource_cls, jlong entry_token, const char *resource_path, jstring resourcePath) {
    if (!env || !resource_cls || entry_token == 0 || !resource_path || !resourcePath || !js_vm_preload_in_progress) return NULL;
    const js_vm_call_gate_entry *gate = js_vm_call_gate_lookup(entry_token);
    if (!gate || !gate->active || strcmp(gate->resource_path, resource_path) != 0) return NULL;
    js_vm_program *cached = js_vm_ephemeral_cache_get(entry_token, resource_path);
    if (cached) return cached;
    if (!js_vm_call_gate_mark_loading(entry_token, resource_path)) return NULL;
    js_vm_program *program = js_vm_prepare_resource_program_bound(env, resource_cls, entry_token, resourcePath, resource_path);
    if (program) {
        js_vm_program validation;
        memset(&validation, 0, sizeof(validation));
        if (!js_vm_build_execution_program_from_registers(program, &validation)) {
            char reason[384];
            snprintf(reason, sizeof(reason), "native VM preload validation failed at %s#%s%s err=%d reg=%d super=%d insn=%d",
                program->original_owner ? program->original_owner : "?",
                program->original_name ? program->original_name : "?",
                program->original_desc ? program->original_desc : "?",
                js_vm_last_validation_error, program->reg_program.insn_count, program->reg_program.super_count, program->insn_count);
            js_vm_clear_execution_program(&validation);
            js_vm_free_program(env, program);
            free(program);
            js_vm_call_gate_clear_loading(entry_token);
            js_vm_fail_closed(env, reason);
            return NULL;
        } else {
            js_vm_clear_execution_program(&validation);
        }
    }
    if (program && !js_vm_ephemeral_cache_put(entry_token, resource_path, program)) {
        js_vm_free_program(env, program);
        free(program);
        program = NULL;
    }
    js_vm_call_gate_clear_loading(entry_token);
    return program;
}

JS_HIDDEN jobject js_vm_execute_cached_program(JNIEnv *env, jclass resource_cls, js_vm_program *program, jobjectArray args) {
    if (!program) {
        return js_vm_fail_closed(env, "native VM resource was not preloaded");
    }
    /* Bind the calling class loader for this dispatch frame so VM symbol resolution
     * can resolve application classes from native call contexts. */
    jobject saved_host_loader = js_vm_get_active_host_loader();
    jobject host_loader_ref = NULL;
    if (resource_cls) {
        jobject host_loader = js_vm_helper_class_loader(env, resource_cls);
        if (host_loader) {
            host_loader_ref = (*env)->NewLocalRef(env, host_loader);
            if (host_loader_ref) js_vm_set_active_host_loader(host_loader_ref);
            (*env)->DeleteLocalRef(env, host_loader);
        }
    }
    js_vm_object_result result = js_vm_execute_prepared_program(env, program, args);
    js_vm_set_active_host_loader(saved_host_loader);
    if (host_loader_ref) (*env)->DeleteLocalRef(env, host_loader_ref);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return result.ok ? result.value : js_vm_fail_closed(env, NULL);
}

JS_HIDDEN jobject js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args) {
    if (!resourcePath || entry_token == 0) return js_vm_fail_closed(env, NULL);
    if (!js_vm_execute_hot_path_self_check()) {
       return js_vm_fail_closed(env, NULL);
    }
    const char *resource_path = j2c(env, resourcePath);
    js_vm_program *program = resource_path ? js_vm_ephemeral_cache_get(entry_token, resource_path) : NULL;
    if (!program && resource_path && js_vm_preload_in_progress) {
        program = js_vm_preload_indexed_program_on_demand(env, resource_cls, entry_token, resource_path, resourcePath);
    }
    if (resource_path) rls(env, resourcePath, resource_path);
    if ((*env)->ExceptionCheck(env)) {
        return NULL;
    }
    return js_vm_execute_cached_program(env, resource_cls, program, args);
}

JS_HIDDEN jobject js_vm_execute_resource_by_token(JNIEnv *env, jclass resource_cls, jlong entry_token, jobjectArray args) {
    if (entry_token == 0) return js_vm_fail_closed(env, NULL);
    if (!js_vm_execute_hot_path_self_check()) {
       return js_vm_fail_closed(env, NULL);
    }
    const js_vm_call_gate_entry *gate = js_vm_call_gate_lookup(entry_token);
    if (!gate || !gate->active || !gate->resource_path[0]) {
        return js_vm_fail_closed(env, "native VM token was not preloaded");
    }
    js_vm_program *program = js_vm_ephemeral_cache_get(entry_token, gate->resource_path);
    return js_vm_execute_cached_program(env, resource_cls, program, args);
}

JS_HIDDEN js_vm_program* js_vm_find_preloaded_program_by_method(unsigned long long class_hash, unsigned long long meth_hash, unsigned long long sig_hash) {
    if (class_hash == 0ULL || meth_hash == 0ULL || sig_hash == 0ULL) return NULL;
    js_vm_program *active = js_vm_active_program_find_by_method(class_hash, meth_hash, sig_hash);
    if (active) return active;
    return js_vm_ephemeral_cache_find_by_method(class_hash, meth_hash, sig_hash);
}

JS_HIDDEN js_vm_program* js_vm_ephemeral_cache_get(jlong entry_token, const char *resource_path) {
    if (!resource_path) return NULL;
    js_vm_cache_lock_enter();
    for (js_vm_ephemeral_cache_entry *entry = js_vm_ephemeral_cache; entry; entry = entry->next) {
        if (entry->entry_token == entry_token && entry->resource_path && strcmp(entry->resource_path, resource_path) == 0) {
            js_vm_program *program = entry->program;
            js_vm_cache_lock_leave();
            return program;
        }
    }
    js_vm_cache_lock_leave();
    return NULL;
}

JS_HIDDEN js_vm_program* js_vm_ephemeral_cache_find_by_method(unsigned long long class_hash, unsigned long long meth_hash, unsigned long long sig_hash) {
    if (class_hash == 0ULL || meth_hash == 0ULL || sig_hash == 0ULL) return NULL;
    js_vm_cache_lock_enter();
    js_vm_program *found = NULL;
    for (js_vm_ephemeral_cache_entry *entry = js_vm_ephemeral_cache; entry; entry = entry->next) {
        js_vm_program *program = entry->program;
        if (program && program->original_owner_hash == class_hash &&
            program->original_name_hash == meth_hash &&
            program->original_desc_hash == sig_hash) {
            found = program;
            break;
        }
    }
    js_vm_cache_lock_leave();
    return found;
}

JS_HIDDEN int js_vm_ephemeral_cache_put(jlong entry_token, const char *resource_path, js_vm_program *program) {
    if (!resource_path || !program) return 0;
    js_vm_cache_lock_enter();
    for (js_vm_ephemeral_cache_entry *existing = js_vm_ephemeral_cache; existing; existing = existing->next) {
        if (existing->entry_token == entry_token && existing->resource_path && strcmp(existing->resource_path, resource_path) == 0) {
            js_vm_cache_lock_leave();
            return 1;
        }
    }
    js_vm_ephemeral_cache_entry *entry = (js_vm_ephemeral_cache_entry*)calloc(1, sizeof(js_vm_ephemeral_cache_entry));
    if (!entry) {
        js_vm_cache_lock_leave();
        return 0;
    }
    entry->resource_path = js_strdup(resource_path);
    if (!entry->resource_path) {
        free(entry);
        js_vm_cache_lock_leave();
        return 0;
    }
    entry->entry_token = entry_token;
    entry->program = program;
    entry->next = js_vm_ephemeral_cache;
    js_vm_ephemeral_cache = entry;
    js_vm_cache_lock_leave();
    return 1;
}

JS_HIDDEN void js_vm_ephemeral_cache_clear(JNIEnv *env) {
    js_vm_cache_lock_enter();
    js_vm_ephemeral_cache_entry *entry = js_vm_ephemeral_cache;
    js_vm_ephemeral_cache = NULL;
    js_vm_cache_lock_leave();
    while (entry) {
        js_vm_ephemeral_cache_entry *next = entry->next;
        if (entry->program) { js_vm_free_program(env, entry->program); free(entry->program); }
        if (entry->resource_path) { js_vbc4_wipe_volatile(entry->resource_path, strlen(entry->resource_path)); free(entry->resource_path); }
        js_vbc4_wipe_volatile(entry, sizeof(*entry));
        free(entry);
        entry = next;
    }
}
