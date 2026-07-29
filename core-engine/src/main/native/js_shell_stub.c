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
#elif defined(__APPLE__) || defined(__linux__)
#include <dlfcn.h>
#endif

static js_shell_loaded_image g_inner_image;
static const js_native_abi_table *g_inner_abi = 0;
static JavaVM *g_shell_vm = 0;
static jclass g_shell_helper_class = 0;
static volatile int g_shell_loaded = 0;
static volatile int g_shell_failed = 0;
static volatile int g_inner_onload_done = 0;
static volatile const char g_js_shell_stub_marker[] = JS_NATIVE_MAX_STUB_MARKER;

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
    unsigned char section_digest_hmac[32];
    const unsigned char *binding_tag;
    const unsigned char *chunk_tags;
    unsigned char *sensitive_header;
    size_t sensitive_header_size;
    size_t chunk_tags_size;
    unsigned char nonce[16];
} js_shell_payload_meta;

static unsigned char *js_shell_alloc(size_t size);
static void js_shell_wipe_free(unsigned char *bytes, size_t size);
static int js_shell_verify_inner_digest(const unsigned char stream_key[32], const unsigned char *decoded, size_t decoded_size, const unsigned char expected[32]);
static int js_shell_verify_build_hmac(const unsigned char boot_secret[32], const unsigned char nonce[16]);

static int js_shell_hex_nibble(unsigned char value) {
    if (value >= '0' && value <= '9') return (int)(value - '0');
    if (value >= 'a' && value <= 'f') return (int)(value - 'a') + 10;
    if (value >= 'A' && value <= 'F') return (int)(value - 'A') + 10;
    return -1;
}

static int js_shell_ascii_space(unsigned char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static int js_shell_decode_boot_hex(const char *value, unsigned char out[32]) {
    const unsigned char *start, *end;
    if (!value) return 0;
    start = (const unsigned char *)value;
    end = start + strlen(value);
    while (start < end && js_shell_ascii_space(*start)) start++;
    while (end > start && js_shell_ascii_space(*(end - 1u))) end--;
    if ((size_t)(end - start) != 64u) return 0;
    for (size_t i = 0; i < 32u; i++) {
        int high = js_shell_hex_nibble(start[i * 2u]);
        int low = js_shell_hex_nibble(start[i * 2u + 1u]);
        if (high < 0 || low < 0) return 0;
        out[i] = (unsigned char)((high << 4) | low);
    }
    return 1;
}

static int js_shell_boot_secret_from_file(const char *path, unsigned char out[32]) {
    unsigned char bytes[4097];
    unsigned char hex[65];
    FILE *file;
    size_t size, start, end;
    int read_error, trailing;
    memset(bytes, 0, sizeof(bytes));
    if (!path || !path[0]) return 0;
    file = fopen(path, "rb");
    if (!file) return 0;
    size = fread(bytes, 1u, sizeof(bytes), file);
    trailing = fgetc(file);
    read_error = ferror(file);
    fclose(file);
    if (read_error || trailing != EOF) { js_shell_secure_wipe(bytes, sizeof(bytes)); return 0; }
    if (size == 32u) memcpy(out, bytes, 32u);
    else {
        start = 0u;
        end = size;
        while (start < end && js_shell_ascii_space(bytes[start])) start++;
        while (end > start && js_shell_ascii_space(bytes[end - 1u])) end--;
        if (end - start != 64u) { js_shell_secure_wipe(bytes, sizeof(bytes)); return 0; }
        memcpy(hex, bytes + start, 64u);
        hex[64] = 0;
        if (!js_shell_decode_boot_hex((const char *)hex, out)) {
            js_shell_secure_wipe(hex, sizeof(hex));
            js_shell_secure_wipe(bytes, sizeof(bytes));
            return 0;
        }
        js_shell_secure_wipe(hex, sizeof(hex));
    }
    js_shell_secure_wipe(bytes, sizeof(bytes));
    return 1;
}

static int js_shell_load_boot_secret(unsigned char out[32]) {
    memset(out, 0, 32u);
    const char *encoded = getenv("JAVASHROUD_BOOT_SECRET_V1");
    if (encoded && encoded[0]) {
        if (js_shell_decode_boot_hex(encoded, out)) return 1;
        js_shell_secure_wipe(out, 32u);
        return 0;
    }
    return js_shell_boot_secret_from_file(getenv("JAVASHROUD_BOOT_SECRET_FILE_V1"), out);
}

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

static int js_shell_extract_meta(
    js_shell_payload_meta *meta,
    unsigned char stream_key[32],
    const unsigned char artifact_binding_commitment[32]) {
    size_t offset = 0;
    size_t sensitive_offset = 0u;
    unsigned int version = 0, level = 0, nonce_size = 0, seed_nonce_size = 0, encrypted_header_size = 0, chunk_tags_size = 0;
    unsigned char boot_secret[32], shell_seed[32], seed_nonce[16], expected_binding_commitment[32];
    unsigned char *sensitive = 0;
    const unsigned char *encrypted_seed = 0, *seed_tag = 0, *encrypted_header = 0, *header_tag = 0;
    if (!meta || !stream_key || !artifact_binding_commitment) return 0;
    memset(boot_secret, 0, sizeof(boot_secret));
    memset(shell_seed, 0, sizeof(shell_seed));
    memset(seed_nonce, 0, sizeof(seed_nonce));
    memset(expected_binding_commitment, 0, sizeof(expected_binding_commitment));
    memset(meta, 0, sizeof(*meta));
    memset(stream_key, 0, 32u);
    while (offset < JS_SHELL_PAYLOAD_HEADER_SIZE && js_shell_payload_header[offset] != 0) offset++;
    if (offset >= JS_SHELL_PAYLOAD_HEADER_SIZE) return 0;
    if (offset != sizeof(JS_NATIVE_MAX_PAYLOAD_MARKER) - 1u || memcmp(js_shell_payload_header, JS_NATIVE_MAX_PAYLOAD_MARKER, offset) != 0 || g_js_shell_stub_marker[0] != 'J') return 0;
    offset++;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &version)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &level)) return 0;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &nonce_size)) return 0;
    if (version != JS_SHELL_PROTOCOL_VERSION || level != 2u || nonce_size != 16u || offset > JS_SHELL_PAYLOAD_HEADER_SIZE || JS_SHELL_PAYLOAD_HEADER_SIZE - offset < 16u) return 0;
    memcpy(meta->nonce, js_shell_payload_header + offset, 16u);
    offset += 16u;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &seed_nonce_size) || seed_nonce_size != 16u) return 0;
    if (JS_SHELL_PAYLOAD_HEADER_SIZE - offset < 16u + 32u + 32u + 4u) return 0;
    memcpy(seed_nonce, js_shell_payload_header + offset, 16u); offset += 16u;
    encrypted_seed = js_shell_payload_header + offset; offset += 32u;
    seed_tag = js_shell_payload_header + offset; offset += 32u;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &encrypted_header_size)) return 0;
    if (encrypted_header_size != JS_SHELL_ENCRYPTED_HEADER_SIZE || offset > JS_SHELL_PAYLOAD_HEADER_SIZE || JS_SHELL_PAYLOAD_HEADER_SIZE - offset != (size_t)encrypted_header_size + 32u) return 0;
    encrypted_header = js_shell_payload_header + offset; offset += (size_t)encrypted_header_size;
    header_tag = js_shell_payload_header + offset;
    if (!js_shell_load_boot_secret(boot_secret) ||
        !js_shell_verify_build_hmac(boot_secret, meta->nonce) ||
        !js_shell_open_seed_envelope(boot_secret, seed_nonce, encrypted_seed, seed_tag, shell_seed)) goto fail;
    sensitive = js_shell_alloc((size_t)encrypted_header_size);
    if (!sensitive || !js_shell_open_sensitive_header(shell_seed, meta->nonce, encrypted_header, (size_t)encrypted_header_size, header_tag, sensitive)) goto fail;
    if (!js_shell_skip_string(sensitive, encrypted_header_size, &sensitive_offset) || !js_shell_skip_string(sensitive, encrypted_header_size, &sensitive_offset) || !js_shell_skip_string(sensitive, encrypted_header_size, &sensitive_offset)) goto fail;
    if (!js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->original_size) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->stored_size) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->encoded_size) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->compression_codec) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->chunk_size) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->chunk_count) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->layout_profile) || !js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &meta->dispatcher_profile)) goto fail;
    if (sensitive_offset > encrypted_header_size || encrypted_header_size - sensitive_offset < 64u) goto fail;
    memcpy(meta->section_digest_hmac, sensitive + sensitive_offset, 32u); sensitive_offset += 32u;
    meta->binding_tag = sensitive + sensitive_offset; sensitive_offset += 32u;
    js_shell_kdf(boot_secret, "javashroud-native-shell-artifact-binding-v3", meta->nonce, meta->binding_tag, 0u, expected_binding_commitment);
    if (!js_shell_consttime_equal(expected_binding_commitment, artifact_binding_commitment, sizeof(expected_binding_commitment))) goto fail;
    js_shell_derive_stream_key(shell_seed, meta->nonce, meta->binding_tag, stream_key);
    if (!js_shell_read_u32_le(sensitive, encrypted_header_size, &sensitive_offset, &chunk_tags_size)) goto fail;
    if (meta->chunk_count > UINT32_MAX / 32u || chunk_tags_size != meta->chunk_count * 32u || sensitive_offset > encrypted_header_size || (size_t)chunk_tags_size != encrypted_header_size - sensitive_offset) goto fail;
    meta->chunk_tags = sensitive + sensitive_offset;
    meta->sensitive_header = sensitive;
    meta->sensitive_header_size = (size_t)encrypted_header_size;
    meta->chunk_tags_size = (size_t)chunk_tags_size;
    if (meta->original_size == 0u || meta->stored_size == 0u || meta->stored_size != meta->encoded_size || meta->encoded_size != JS_SHELL_PAYLOAD_SIZE || (meta->compression_codec != JS_SHELL_COMPRESSION_NONE && meta->compression_codec != JS_SHELL_COMPRESSION_ZSTD) || meta->chunk_size == 0u || meta->chunk_count != 1u + (meta->encoded_size - 1u) / meta->chunk_size) goto fail;
    {
        unsigned int binding_acc = 0u;
        for (size_t i=0;i<32u;i++) binding_acc |= (unsigned int)meta->binding_tag[i];
        if (binding_acc == 0u) goto fail;
    }
    js_shell_secure_wipe(boot_secret,sizeof(boot_secret)); js_shell_secure_wipe(shell_seed,sizeof(shell_seed)); js_shell_secure_wipe(expected_binding_commitment,sizeof(expected_binding_commitment));
    /* Keep the decrypted header alive only through payload decode. */
    return 1;
fail:
    js_shell_secure_wipe(boot_secret,sizeof(boot_secret)); js_shell_secure_wipe(shell_seed,sizeof(shell_seed)); js_shell_secure_wipe(expected_binding_commitment,sizeof(expected_binding_commitment)); js_shell_secure_wipe(stream_key, 32u);
    if (sensitive) js_shell_wipe_free(sensitive, (size_t)encrypted_header_size);
    return 0;
}

static int js_shell_verify_build_hmac(const unsigned char boot_secret[32], const unsigned char nonce[16]) {
    static const char domain[] = "javashroud-native-shell-build-hmac-v3";
    unsigned char zero_binding[32], commitment_key[32], header_digest[32], payload_digest[32];
    unsigned char digest_pair[64], actual[32];
    js_shell_sha256_ctx ctx;
    int ok;
    memset(zero_binding, 0, sizeof(zero_binding));
    js_shell_kdf(boot_secret, domain, nonce, zero_binding, 0u, commitment_key);
    js_shell_sha256_init(&ctx);
    js_shell_sha256_update(&ctx, js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE);
    js_shell_sha256_final(&ctx, header_digest);
    js_shell_sha256_init(&ctx);
    js_shell_sha256_update(&ctx, js_shell_payload_bytes, JS_SHELL_PAYLOAD_SIZE);
    js_shell_sha256_final(&ctx, payload_digest);
    memcpy(digest_pair, header_digest, sizeof(header_digest));
    memcpy(digest_pair + sizeof(header_digest), payload_digest, sizeof(payload_digest));
    js_shell_hmac_sha256(commitment_key, sizeof(commitment_key), digest_pair, sizeof(digest_pair), actual);
    ok = js_shell_consttime_equal(actual, js_shell_build_hmac, sizeof(actual));
    js_shell_secure_wipe(zero_binding, sizeof(zero_binding));
    js_shell_secure_wipe(commitment_key, sizeof(commitment_key));
    js_shell_secure_wipe(header_digest, sizeof(header_digest));
    js_shell_secure_wipe(payload_digest, sizeof(payload_digest));
    js_shell_secure_wipe(digest_pair, sizeof(digest_pair));
    js_shell_secure_wipe(actual, sizeof(actual));
    return ok;
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

static int js_shell_verify_inner_digest(const unsigned char stream_key[32], const unsigned char *decoded, size_t decoded_size, const unsigned char expected[32]) {
    static const unsigned char domain[] = "javashroud-native-shell-inner-digest-v3";
    unsigned char actual[32];
    unsigned char normalized[64], inner[32];
    js_shell_sha256_ctx ctx;
    int ok;
    memset(normalized, 0, sizeof(normalized));
    memcpy(normalized, stream_key, 32u);
    for (size_t i=0;i<64u;i++) normalized[i]^=0x36u;
    js_shell_sha256_init(&ctx); js_shell_sha256_update(&ctx, normalized, sizeof(normalized));
    js_shell_sha256_update(&ctx, domain, sizeof(domain)-1u); js_shell_sha256_update(&ctx, decoded, decoded_size); js_shell_sha256_final(&ctx, inner);
    for (size_t i=0;i<64u;i++) normalized[i]^=(unsigned char)(0x36u^0x5cu);
    js_shell_sha256_init(&ctx); js_shell_sha256_update(&ctx, normalized, sizeof(normalized)); js_shell_sha256_update(&ctx, inner, sizeof(inner)); js_shell_sha256_final(&ctx, actual);
    ok = js_shell_consttime_equal(actual, expected, sizeof(actual));
    js_shell_secure_wipe(actual, sizeof(actual));
    js_shell_secure_wipe(normalized, sizeof(normalized));
    js_shell_secure_wipe(inner, sizeof(inner));
    return ok;
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

static void js_shell_debug_native_init_failure(const char *reason) {
    const char *debug = getenv("JAVASHROUD_DEBUG_NATIVE_LOAD");
    if (debug && debug[0] && debug[0] != '0' && reason && reason[0]) {
        fprintf(stderr, "JavaShroud max native shell init failed: %s\n", reason);
    }
}

static int js_shell_debug_enabled(void) {
    const char *debug = getenv("JAVASHROUD_DEBUG_NATIVE_LOAD");
    return debug && debug[0] && debug[0] != '0';
}

static void js_shell_debug_env_probe(const char *label, JNIEnv *incoming, JNIEnv *current, jint status) {
    if (!js_shell_debug_enabled()) return;
    const char *log_path = getenv("JAVASHROUD_DEBUG_NATIVE_LOG");
    FILE *out = stderr;
    if (log_path && log_path[0]) {
        FILE *file = fopen(log_path, "ab");
        if (file) out = file;
    }
    fprintf(out,
        "JavaShroud max native shell env probe: %s incoming=%p current=%p getEnv=%d vm=%p innerLoaded=%d innerOnLoad=%d failed=%d\n",
        label ? label : "<null>",
        (void *)incoming,
        (void *)current,
        (int)status,
        (void *)g_shell_vm,
        (int)g_shell_loaded,
        (int)g_inner_onload_done,
        (int)g_shell_failed);
    if (out != stderr) fclose(out);
}

static JNIEnv *js_shell_current_env_for(const char *label, JNIEnv *incoming) {
    if (incoming) {
        js_shell_debug_env_probe(label, incoming, incoming, JNI_OK);
        return incoming;
    }
    JNIEnv *current = 0;
    jint status = g_shell_vm ? (*g_shell_vm)->GetEnv(g_shell_vm, (void **)&current, JNI_VERSION_1_6) : JNI_ERR;
    js_shell_debug_env_probe(label, incoming, current, status);
    if (status == JNI_OK && current) {
        return current;
    }
    return incoming;
}

static int js_shell_range_contains(const void *base, size_t size, const void *ptr, size_t ptr_size) {
    uintptr_t low = (uintptr_t)base;
    uintptr_t addr = (uintptr_t)ptr;
    if (!base || !ptr || size == 0u || ptr_size == 0u) return 0;
    return addr >= low && addr <= low + size && ptr_size <= low + size - addr;
}

static int js_shell_inner_image_contains(const void *ptr, size_t size) {
    return js_shell_range_contains(g_inner_image.image_base, g_inner_image.image_size, ptr, size);
}

static int js_shell_inner_code_contains(const void *ptr) {
    if (!g_inner_image.code_low || g_inner_image.code_size == 0u) return 1;
    return js_shell_range_contains(g_inner_image.code_low, g_inner_image.code_size, ptr, 1u);
}

static jclass js_shell_effective_helper_class(jclass fallback) {
    return g_shell_helper_class ? g_shell_helper_class : fallback;
}

static JNIEnv *js_shell_current_env(JNIEnv *incoming) {
    return js_shell_current_env_for("current-env", incoming);
}

static int js_shell_validate_inner_abi_table(const js_native_abi_table *abi) {
    if (!abi || !js_shell_inner_image_contains(abi, sizeof(*abi))) {
        js_shell_debug_native_init_failure("inner ABI table pointer is outside the mapped image");
        return 0;
    }
    if (abi->version != JS_NATIVE_ABI_TABLE_VERSION) {
        js_shell_debug_native_init_failure("inner ABI table version mismatch");
        return 0;
    }
    const void *functions[] = {
        (const void *)abi->native_init,
        (const void *)abi->native_verify,
        (const void *)abi->native_heartbeat,
        (const void *)abi->native_decrypt_aes,
        (const void *)abi->native_get_version,
        (const void *)abi->native_get_boot_token,
        (const void *)abi->native_install_boot_material,
        (const void *)abi->native_is_boot_material_ready,
        (const void *)abi->native_abort_boot_material,
        (const void *)abi->native_preload_runtime_resources,
        (const void *)abi->native_derive_class_encryption_key,
        (const void *)abi->execute_vm_resource,
        (const void *)abi->execute_vm_resource_by_token,
        (const void *)abi->execute_vm_resource_void,
        (const void *)abi->execute_vm_resource_int,
        (const void *)abi->execute_vm_resource_int_int,
        (const void *)abi->execute_vm_resource_int_void,
    };
    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); i++) {
        if (!functions[i] || !js_shell_inner_code_contains(functions[i])) {
            js_shell_debug_native_init_failure("inner ABI function pointer is outside executable image pages");
            return 0;
        }
    }
    return 1;
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

static void js_shell_native_install_boot_name(char out[26]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Install", 7u);
    memcpy(out + 13u, "BootMaterial", 12u);
    out[25] = 0;
}

static void js_shell_native_boot_ready_name(char out[26]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Is", 2u);
    memcpy(out + 8u, "BootMaterial", 12u);
    memcpy(out + 20u, "Ready", 5u);
    out[25] = 0;
}

static void js_shell_native_abort_boot_name(char out[24]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Abort", 5u);
    memcpy(out + 11u, "BootMaterial", 12u);
    out[23] = 0;
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

static void js_shell_native_execute_int_name(char out[27]) {
    js_shell_native_execute_name(out);
    memcpy(out + 23u, "Int", 4u);
}

static void js_shell_native_execute_int_int_name(char out[30]) {
    js_shell_native_execute_name(out);
    memcpy(out + 23u, "Int", 3u);
    memcpy(out + 26u, "Int", 4u);
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

static int js_shell_take_expected_binding_commitment(JNIEnv *env, unsigned char out[32]) {
    static const char method_name[] = "takeExpectedShellBindingCommitment";
    jbyte zeros[32] = {0};
    char *owner = 0;
    jclass helper_cls = 0;
    jmethodID method = 0;
    jbyteArray value = 0;
    int ok = 0;
    unsigned int nonzero = 0u;
    if (!env || !out) return 0;
    memset(out, 0, 32u);
    helper_cls = js_shell_find_helper_class(env, &owner);
    if (!helper_cls) goto cleanup;
    method = (*env)->GetStaticMethodID(env, helper_cls, method_name, "()[B");
    if ((*env)->ExceptionCheck(env) || !method) goto cleanup;
    value = (jbyteArray)(*env)->CallStaticObjectMethod(env, helper_cls, method);
    if ((*env)->ExceptionCheck(env) || !value || (*env)->GetArrayLength(env, value) != 32) goto cleanup;
    (*env)->GetByteArrayRegion(env, value, 0, 32, (jbyte *)out);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, value, 0, 32, zeros);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    for (size_t i = 0; i < 32u; i++) nonzero |= (unsigned int)out[i];
    ok = nonzero != 0u;
cleanup:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (value) (*env)->DeleteLocalRef(env, value);
    if (helper_cls) (*env)->DeleteLocalRef(env, helper_cls);
    free(owner);
    if (!ok) js_shell_secure_wipe(out, 32u);
    js_shell_secure_wipe(zeros, sizeof(zeros));
    return ok;
}

static jint JNICALL js_shell_native_init(JNIEnv *env, jclass cls, jstring platform) {
    JNIEnv *call_env = js_shell_current_env_for("native-init", env);
    if (!call_env) return JNI_ERR;
    if (!g_inner_image.jni_on_load || !g_shell_vm || g_shell_failed) return JNI_ERR;
    if (!g_inner_onload_done) {
        if (!js_shell_inner_code_contains((const void *)g_inner_image.jni_on_load)) {
            js_shell_debug_native_init_failure("inner JNI_OnLoad is outside executable image pages");
            g_shell_failed = 1;
            return JNI_ERR;
        }
        js_shell_debug_env_probe("before-inner-onload", env, call_env, JNI_OK);
        jint loaded = g_inner_image.jni_on_load(g_shell_vm, 0);
        js_shell_debug_env_probe("after-inner-onload", env, call_env, JNI_OK);
        if ((*call_env)->ExceptionCheck(call_env)) return JNI_ERR;
        if (loaded == JNI_ERR || loaded == 0) { g_shell_failed = 1; return JNI_ERR; }
        if (!g_inner_image.native_abi_table_v1 || !js_shell_inner_code_contains((const void *)g_inner_image.native_abi_table_v1)) {
            js_shell_debug_native_init_failure("inner ABI table export is outside executable image pages");
            g_shell_failed = 1;
            return JNI_ERR;
        }
        g_inner_abi = g_inner_image.native_abi_table_v1();
        if (!js_shell_validate_inner_abi_table(g_inner_abi)) {
            g_shell_failed = 1;
            return JNI_ERR;
        }
        if (!js_shell_register_outer_shim(call_env)) {
            g_shell_failed = 1;
            return JNI_ERR;
        }
        g_inner_onload_done = 1;
        g_shell_loaded = 1;
        return 2;
    }
    return g_inner_abi && g_inner_abi->native_init ? g_inner_abi->native_init(call_env, js_shell_effective_helper_class(cls), platform) : JNI_ERR;
}

static jint JNICALL js_shell_native_verify(JNIEnv *env, jclass cls, jbyteArray data, jbyteArray expected_mac) {
    JNIEnv *call_env = js_shell_current_env_for("native-verify", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->native_verify) return 0;
    return g_inner_abi->native_verify(call_env, js_shell_effective_helper_class(cls), data, expected_mac);
}

static jint JNICALL js_shell_native_heartbeat(JNIEnv *env, jclass cls) {
    JNIEnv *call_env = js_shell_current_env_for("native-heartbeat", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->native_heartbeat) return 0;
    return g_inner_abi->native_heartbeat(call_env, js_shell_effective_helper_class(cls));
}

static jbyteArray JNICALL js_shell_native_decrypt_aes(JNIEnv *env, jclass cls, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr) {
    JNIEnv *call_env = js_shell_current_env_for("native-decrypt-aes", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->native_decrypt_aes) return 0;
    return g_inner_abi->native_decrypt_aes(call_env, js_shell_effective_helper_class(cls), encrypted, keyArr, ivArr);
}

static jstring JNICALL js_shell_native_get_version(JNIEnv *env, jclass cls) {
    JNIEnv *call_env = js_shell_current_env_for("native-get-version", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->native_get_version) return 0;
    return g_inner_abi->native_get_version(call_env, js_shell_effective_helper_class(cls));
}

static jlong JNICALL js_shell_native_get_boot_token(JNIEnv *env, jclass cls) {
    JNIEnv *call_env = js_shell_current_env_for("native-get-boot-token", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->native_get_boot_token) return 0;
    return g_inner_abi->native_get_boot_token(call_env, js_shell_effective_helper_class(cls));
}

static jboolean JNICALL js_shell_native_install_boot_material(JNIEnv *env, jclass cls, jbyteArray material) {
    JNIEnv *call_env = js_shell_current_env_for("native-install-boot-material", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->native_install_boot_material) return JNI_FALSE;
    return g_inner_abi->native_install_boot_material(call_env, js_shell_effective_helper_class(cls), material);
}

static jboolean JNICALL js_shell_native_is_boot_material_ready(JNIEnv *env, jclass cls) {
    JNIEnv *call_env = js_shell_current_env_for("native-is-boot-material-ready", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->native_is_boot_material_ready) return JNI_FALSE;
    return g_inner_abi->native_is_boot_material_ready(call_env, js_shell_effective_helper_class(cls));
}

static void JNICALL js_shell_native_abort_boot_material(JNIEnv *env, jclass cls) {
    JNIEnv *call_env = js_shell_current_env_for("native-abort-boot-material", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->native_abort_boot_material) return;
    g_inner_abi->native_abort_boot_material(call_env, js_shell_effective_helper_class(cls));
}

static void JNICALL js_shell_native_preload_runtime_resources(JNIEnv *env, jclass cls, jbyteArray preload_index, jbyteArray commitments, jbyteArray startup_nonce) {
    JNIEnv *call_env = js_shell_current_env_for("native-preload-runtime-resources", env);
    if (!call_env) return;
    if (!g_inner_abi || !g_inner_abi->native_preload_runtime_resources) return;
    g_inner_abi->native_preload_runtime_resources(call_env, js_shell_effective_helper_class(cls), preload_index, commitments, startup_nonce);
}

static jbyteArray JNICALL js_shell_native_derive_class_encryption_key(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length) {
    JNIEnv *call_env = js_shell_current_env_for("native-derive-class-encryption-key", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->native_derive_class_encryption_key) return 0;
    return g_inner_abi->native_derive_class_encryption_key(call_env, js_shell_effective_helper_class(cls), keyIdArr, saltArr, length);
}

static jobject JNICALL js_shell_execute_vm_resource(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args) {
    JNIEnv *call_env = js_shell_current_env_for("execute-vm-resource", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource) return 0;
    return g_inner_abi->execute_vm_resource(call_env, js_shell_effective_helper_class(cls), entryToken, resourcePath, args);
}

static jobject JNICALL js_shell_execute_vm_resource_by_token(JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args) {
    JNIEnv *call_env = js_shell_current_env_for("execute-vm-resource-by-token", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_by_token) return 0;
    return g_inner_abi->execute_vm_resource_by_token(call_env, js_shell_effective_helper_class(cls), entryToken, args);
}

static void JNICALL js_shell_execute_vm_resource_void(JNIEnv *env, jclass cls, jlong entryToken) {
    JNIEnv *call_env = js_shell_current_env_for("execute-vm-resource-void", env);
    if (!call_env) return;
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_void) return;
    g_inner_abi->execute_vm_resource_void(call_env, js_shell_effective_helper_class(cls), entryToken);
}

static jint JNICALL js_shell_execute_vm_resource_int(JNIEnv *env, jclass cls, jlong entryToken) {
    JNIEnv *call_env = js_shell_current_env_for("execute-vm-resource-int", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_int) return 0;
    return g_inner_abi->execute_vm_resource_int(call_env, js_shell_effective_helper_class(cls), entryToken);
}

static jint JNICALL js_shell_execute_vm_resource_int_int(JNIEnv *env, jclass cls, jlong entryToken, jint arg0) {
    JNIEnv *call_env = js_shell_current_env_for("execute-vm-resource-int-int", env);
    if (!call_env) return 0;
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_int_int) return 0;
    return g_inner_abi->execute_vm_resource_int_int(call_env, js_shell_effective_helper_class(cls), entryToken, arg0);
}

static void JNICALL js_shell_execute_vm_resource_int_void(JNIEnv *env, jclass cls, jlong entryToken, jint arg0) {
    JNIEnv *call_env = js_shell_current_env_for("execute-vm-resource-int-void", env);
    if (!call_env) return;
    if (!g_inner_abi || !g_inner_abi->execute_vm_resource_int_void) return;
    g_inner_abi->execute_vm_resource_int_void(call_env, js_shell_effective_helper_class(cls), entryToken, arg0);
}

static int js_shell_register_outer_shim(JNIEnv *env) {
    char *owner = 0;
    char *original_owner = 0;
    char *mapped_init = 0, *mapped_verify = 0, *mapped_heartbeat = 0, *mapped_version = 0, *mapped_boot_token = 0;
    char *mapped_install_boot = 0, *mapped_boot_ready = 0, *mapped_abort_boot = 0, *mapped_preload = 0, *mapped_decrypt_aes = 0, *mapped_class_key = 0;
    char *mapped_exec = 0, *mapped_exec_token = 0, *mapped_void = 0, *mapped_int = 0, *mapped_int_int = 0, *mapped_int_void = 0;
    int ok;
    jclass helper_cls = js_shell_find_helper_class(env, &owner);
    if (!helper_cls || !owner) return 0;
    char native_init_name[11];
    char native_verify_name[13];
    char native_heartbeat_name[16];
    char native_version_name[17];
    char native_boot_token_name[19];
    char native_install_boot_name[26];
    char native_boot_ready_name[26];
    char native_abort_boot_name[24];
    char native_preload_name[30];
    char native_decrypt_aes_name[17];
    char native_class_key_name[31];
    char native_exec_name[24];
    char native_exec_token_name[31];
    char native_void_name[28];
    char native_int_name[27];
    char native_int_int_name[30];
    char native_int_void_name[31];
    js_shell_native_init_name(native_init_name);
    js_shell_native_verify_name(native_verify_name);
    js_shell_native_heartbeat_name(native_heartbeat_name);
    js_shell_native_version_name(native_version_name);
    js_shell_native_boot_token_name(native_boot_token_name);
    js_shell_native_install_boot_name(native_install_boot_name);
    js_shell_native_boot_ready_name(native_boot_ready_name);
    js_shell_native_abort_boot_name(native_abort_boot_name);
    js_shell_native_preload_name(native_preload_name);
    js_shell_native_decrypt_aes_name(native_decrypt_aes_name);
    js_shell_native_class_key_name(native_class_key_name);
    js_shell_native_execute_name(native_exec_name);
    js_shell_native_execute_by_token_name(native_exec_token_name);
    js_shell_native_execute_void_name(native_void_name);
    js_shell_native_execute_int_name(native_int_name);
    js_shell_native_execute_int_int_name(native_int_int_name);
    js_shell_native_execute_int_void_name(native_int_void_name);
    original_owner = js_shell_default_helper_owner();
    mapped_init = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_init_name, "(Ljava/lang/String;)I") : 0;
    mapped_verify = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_verify_name, "([B[B)I") : 0;
    mapped_heartbeat = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_heartbeat_name, "()I") : 0;
    mapped_version = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_version_name, "()Ljava/lang/String;") : 0;
    mapped_boot_token = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_boot_token_name, "()J") : 0;
    mapped_install_boot = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_install_boot_name, "([B)Z") : 0;
    mapped_boot_ready = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_boot_ready_name, "()Z") : 0;
    mapped_abort_boot = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_abort_boot_name, "()V") : 0;
    mapped_preload = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_preload_name, "([B[B[B)V") : 0;
    mapped_decrypt_aes = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_decrypt_aes_name, "([B[B[B)[B") : 0;
    mapped_class_key = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_class_key_name, "([B[BI)[B") : 0;
    mapped_exec = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_exec_name, "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;") : 0;
    mapped_exec_token = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_exec_token_name, "(J[Ljava/lang/Object;)Ljava/lang/Object;") : 0;
    mapped_void = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_void_name, "(J)V") : 0;
    mapped_int = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_name, "(J)I") : 0;
    mapped_int_int = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_int_name, "(JI)I") : 0;
    mapped_int_void = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_void_name, "(JI)V") : 0;
    JNINativeMethod methods[17];
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
    methods[5].name = (char *)((mapped_install_boot && mapped_install_boot[0]) ? mapped_install_boot : native_install_boot_name);
    methods[5].signature = "([B)Z";
    methods[5].fnPtr = (void *)js_shell_native_install_boot_material;
    methods[6].name = (char *)((mapped_boot_ready && mapped_boot_ready[0]) ? mapped_boot_ready : native_boot_ready_name);
    methods[6].signature = "()Z";
    methods[6].fnPtr = (void *)js_shell_native_is_boot_material_ready;
    methods[7].name = (char *)((mapped_abort_boot && mapped_abort_boot[0]) ? mapped_abort_boot : native_abort_boot_name);
    methods[7].signature = "()V";
    methods[7].fnPtr = (void *)js_shell_native_abort_boot_material;
    methods[8].name = (char *)((mapped_preload && mapped_preload[0]) ? mapped_preload : native_preload_name);
    methods[8].signature = "([B[B[B)V";
    methods[8].fnPtr = (void *)js_shell_native_preload_runtime_resources;
    methods[9].name = (char *)((mapped_decrypt_aes && mapped_decrypt_aes[0]) ? mapped_decrypt_aes : native_decrypt_aes_name);
    methods[9].signature = "([B[B[B)[B";
    methods[9].fnPtr = (void *)js_shell_native_decrypt_aes;
    methods[10].name = (char *)((mapped_class_key && mapped_class_key[0]) ? mapped_class_key : native_class_key_name);
    methods[10].signature = "([B[BI)[B";
    methods[10].fnPtr = (void *)js_shell_native_derive_class_encryption_key;
    methods[11].name = (char *)((mapped_exec && mapped_exec[0]) ? mapped_exec : native_exec_name);
    methods[11].signature = "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[11].fnPtr = (void *)js_shell_execute_vm_resource;
    methods[12].name = (char *)((mapped_exec_token && mapped_exec_token[0]) ? mapped_exec_token : native_exec_token_name);
    methods[12].signature = "(J[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[12].fnPtr = (void *)js_shell_execute_vm_resource_by_token;
    methods[13].name = (char *)((mapped_void && mapped_void[0]) ? mapped_void : native_void_name);
    methods[13].signature = "(J)V";
    methods[13].fnPtr = (void *)js_shell_execute_vm_resource_void;
    methods[14].name = (char *)((mapped_int_void && mapped_int_void[0]) ? mapped_int_void : native_int_void_name);
    methods[14].signature = "(JI)V";
    methods[14].fnPtr = (void *)js_shell_execute_vm_resource_int_void;
    methods[15].name = (char *)((mapped_int && mapped_int[0]) ? mapped_int : native_int_name);
    methods[15].signature = "(J)I";
    methods[15].fnPtr = (void *)js_shell_execute_vm_resource_int;
    methods[16].name = (char *)((mapped_int_int && mapped_int_int[0]) ? mapped_int_int : native_int_int_name);
    methods[16].signature = "(JI)I";
    methods[16].fnPtr = (void *)js_shell_execute_vm_resource_int_int;
    ok = ((*env)->RegisterNatives(env, helper_cls, methods, (jint)(sizeof(methods) / sizeof(methods[0]))) == 0);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); ok = 0; }
    if (ok && !g_shell_helper_class) {
        jclass global_helper = (jclass)(*env)->NewGlobalRef(env, helper_cls);
        if ((*env)->ExceptionCheck(env) || !global_helper) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            ok = 0;
        } else {
            g_shell_helper_class = global_helper;
        }
    }
    free(mapped_init);
    free(mapped_verify);
    free(mapped_heartbeat);
    free(mapped_version);
    free(mapped_boot_token);
    free(mapped_install_boot);
    free(mapped_boot_ready);
    free(mapped_abort_boot);
    free(mapped_preload);
    free(mapped_decrypt_aes);
    free(mapped_class_key);
    free(mapped_exec);
    free(mapped_exec_token);
    free(mapped_void);
    free(mapped_int);
    free(mapped_int_int);
    free(mapped_int_void);
    free(original_owner);
    free(owner);
    return ok;
}

jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    js_shell_payload_meta meta;
    unsigned char *stored = 0;
    unsigned char *decoded = 0;
    unsigned char stream_key[32];
    unsigned char artifact_binding_commitment[32];
    js_shell_payload_view view;
    JNIEnv *env = 0;
    memset(&view, 0, sizeof(view));
    memset(&meta, 0, sizeof(meta));
    memset(artifact_binding_commitment, 0, sizeof(artifact_binding_commitment));

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env ||
        !js_shell_take_expected_binding_commitment(env, artifact_binding_commitment) ||
        !js_shell_extract_meta(&meta, stream_key, artifact_binding_commitment)) {
        js_shell_secure_wipe(artifact_binding_commitment, sizeof(artifact_binding_commitment));
        return js_shell_fail_onload();
    }
    js_shell_secure_wipe(artifact_binding_commitment, sizeof(artifact_binding_commitment));

    stored = js_shell_alloc((size_t)JS_SHELL_PAYLOAD_SIZE);
    if (!stored) {
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
        return js_shell_fail_onload();
    }
    memcpy(stored, js_shell_payload_bytes, (size_t)JS_SHELL_PAYLOAD_SIZE);
    if (!js_shell_decode_payload_chunks(stored, (size_t)JS_SHELL_PAYLOAD_SIZE, stream_key, meta.nonce, meta.binding_tag, meta.chunk_size, meta.chunk_tags, meta.chunk_tags_size)) {
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        return js_shell_fail_onload();
    }
    if (meta.compression_codec == JS_SHELL_COMPRESSION_NONE) {
        if (meta.stored_size != meta.original_size || meta.stored_size != JS_SHELL_PAYLOAD_SIZE) {
            js_shell_secure_wipe(stream_key, sizeof(stream_key));
            js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
            js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
            return js_shell_fail_onload();
        }
        decoded = stored;
        stored = 0;
    } else if (meta.compression_codec == JS_SHELL_COMPRESSION_ZSTD) {
        size_t written;
        decoded = js_shell_alloc((size_t)meta.original_size);
        if (!decoded) {
            js_shell_secure_wipe(stream_key, sizeof(stream_key));
            js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
            js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
            return js_shell_fail_onload();
        }
        written = ZSTD_decompress(decoded, (size_t)meta.original_size, stored, (size_t)meta.stored_size);
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        stored = 0;
        if (ZSTD_isError(written) || written != (size_t)meta.original_size) {
            js_shell_secure_wipe(stream_key, sizeof(stream_key));
            js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
            js_shell_wipe_free(decoded, (size_t)meta.original_size);
            return js_shell_fail_onload();
        }
    } else {
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
        return js_shell_fail_onload();
    }

    if (!js_shell_verify_inner_digest(stream_key, decoded, (size_t)meta.original_size, meta.section_digest_hmac)) {
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
        js_shell_wipe_free(decoded, (size_t)meta.original_size);
        return js_shell_fail_onload();
    }
    js_shell_secure_wipe(stream_key, sizeof(stream_key));
    js_shell_wipe_free(meta.sensitive_header, meta.sensitive_header_size);
    meta.sensitive_header = 0;

    view.header = js_shell_payload_header;
    view.header_size = JS_SHELL_PAYLOAD_HEADER_SIZE;
    view.payload = js_shell_payload_bytes;
    view.payload_size = JS_SHELL_PAYLOAD_SIZE;
    view.decoded_payload = decoded;
    view.decoded_payload_size = (size_t)meta.original_size;
    view.mac = 0;
    view.mac_size = 0u;
    view.binding_tag = 0;
    view.binding_tag_size = 0u;
    view.layout_profile = meta.layout_profile;
    view.dispatcher_profile = meta.dispatcher_profile;

    if (!js_shell_load_inner_image(&view, &g_inner_image) || !g_inner_image.jni_on_load) {
        js_shell_wipe_free(decoded, (size_t)meta.original_size);
        return js_shell_fail_onload();
    }
    js_shell_wipe_free(decoded, (size_t)meta.original_size);
    g_shell_vm = vm;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env || !js_shell_register_outer_shim(env)) {
        return js_shell_fail_onload();
    }
    return JNI_VERSION_1_6;
}

void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    JNIEnv *env = 0;
    if (vm && (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env && g_shell_helper_class) {
        (*env)->DeleteGlobalRef(env, g_shell_helper_class);
        g_shell_helper_class = 0;
    }
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
