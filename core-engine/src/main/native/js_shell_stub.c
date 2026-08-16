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
    unsigned char binding_tag[32];
    const unsigned char *chunk_tags;
    size_t chunk_tags_size;
    unsigned char nonce[16];
} js_shell_payload_meta;

static unsigned char *js_shell_alloc(size_t size);
static void js_shell_wipe_free(unsigned char *bytes, size_t size);
static int js_shell_verify_inner_digest(const unsigned char stream_key[32], const unsigned char *decoded, size_t decoded_size, const unsigned char expected[32]);
static int js_shell_reconstruct_aken_binding_salt(unsigned char out[32]);
static int js_shell_verify_aken_payload_commitment(const unsigned char binding_salt[32]);
static int js_shell_extract_aken_meta(js_shell_payload_meta *meta, unsigned char stream_key[32], const unsigned char binding_salt[32]);

static unsigned int js_shell_read_u32_le(const unsigned char *bytes, size_t size, size_t *offset, unsigned int *out) {
    size_t at;
    if (!bytes || !offset || !out) return 0u;
    at = *offset;
    if (at > size || size - at < 4u) return 0u;
    *out = (unsigned int)bytes[at] |
        ((unsigned int)bytes[at + 1u] << 8u) |
        ((unsigned int)bytes[at + 2u] << 16u) |
        ((unsigned int)bytes[at + 3u] << 24u);
    *offset = at + 4u;
    return 1u;
}

static unsigned int js_shell_skip_string(const unsigned char *bytes, size_t size, size_t *offset) {
    unsigned int length = 0u;
    size_t at;
    if (!js_shell_read_u32_le(bytes, size, offset, &length)) return 0u;
    at = *offset;
    if (at > size || (size_t)length > size - at) return 0u;
    *offset = at + (size_t)length;
    return 1u;
}

/* Reconstruct the public 32-byte binding material from build-randomized C lanes.
 * The lanes bind a single shell payload; they are integrity data, not a root key. */
static int js_shell_reconstruct_aken_binding_salt(unsigned char out[32]) {
    const unsigned char *lanes[4] = {
        js_shell_aken_binding_lane_0,
        js_shell_aken_binding_lane_1,
        js_shell_aken_binding_lane_2,
        js_shell_aken_binding_lane_3,
    };
    unsigned char seen[4] = {0u, 0u, 0u, 0u};

    if (!out || JS_SHELL_AKEN_BINDING_LANE_COUNT != 4u || JS_SHELL_AKEN_BINDING_LANE_SIZE != 8u) return 0;
    memset(out, 0, 32u);
    for (size_t physical_lane = 0u; physical_lane < 4u; physical_lane++) {
        unsigned int logical_lane = (unsigned int)js_shell_aken_binding_lane_order[physical_lane];
        if (logical_lane >= 4u || seen[logical_lane]) {
            js_shell_secure_wipe(out, 32u);
            js_shell_secure_wipe(seen, sizeof(seen));
            return 0;
        }
        seen[logical_lane] = 1u;
        memcpy(out + ((size_t)logical_lane * 8u), lanes[physical_lane], 8u);
    }
    js_shell_secure_wipe(seen, sizeof(seen));
    return 1;
}

/* Authenticate exactly the generated header and payload before parsing or mapping.
 * This mirrors NativeKernelShellPacker.akenPayloadCommitment:
 * HMAC-SHA256(bindingSalt, domain || SHA256(header) || SHA256(payload)). */
static int js_shell_verify_aken_payload_commitment(const unsigned char binding_salt[32]) {
    static const unsigned char domain[] = "javashroud-aken-v4-native-shell-payload-commitment-v1";
    unsigned char header_digest[32], payload_digest[32], actual[32];
    unsigned char material[(sizeof(domain) - 1u) + 64u];
    js_shell_sha256_ctx ctx;
    int ok = 0;

    if (!binding_salt || sizeof(js_shell_aken_payload_commitment) != 32u) return 0;
    js_shell_sha256_init(&ctx);
    js_shell_sha256_update(&ctx, js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE);
    js_shell_sha256_final(&ctx, header_digest);
    js_shell_sha256_init(&ctx);
    js_shell_sha256_update(&ctx, js_shell_payload_bytes, JS_SHELL_PAYLOAD_SIZE);
    js_shell_sha256_final(&ctx, payload_digest);
    memcpy(material, domain, sizeof(domain) - 1u);
    memcpy(material + sizeof(domain) - 1u, header_digest, sizeof(header_digest));
    memcpy(material + sizeof(domain) - 1u + sizeof(header_digest), payload_digest, sizeof(payload_digest));
    js_shell_hmac_sha256(binding_salt, 32u, material, sizeof(material), actual);
    ok = js_shell_consttime_equal(actual, js_shell_aken_payload_commitment, sizeof(actual));
    js_shell_secure_wipe(header_digest, sizeof(header_digest));
    js_shell_secure_wipe(payload_digest, sizeof(payload_digest));
    js_shell_secure_wipe(actual, sizeof(actual));
    js_shell_secure_wipe(material, sizeof(material));
    return ok;
}

/* Parse AKEN v4 public framing only after the full header/payload commitment has
 * authenticated. There is no boot envelope, provider callback, sidecar, file, or
 * environment lookup in this native shell path. */
static int js_shell_extract_aken_meta(
    js_shell_payload_meta *meta,
    unsigned char stream_key[32],
    const unsigned char binding_salt[32]) {
    size_t offset = 0u;
    size_t metadata_offset = 0u;
    unsigned int version = 0u, level = 0u, nonce_size = 0u, metadata_size = 0u, chunk_tags_size = 0u;
    const unsigned char *metadata = 0;

    if (!meta || !stream_key || !binding_salt) return 0;
    memset(meta, 0, sizeof(*meta));
    memset(stream_key, 0, 32u);

    while (offset < JS_SHELL_PAYLOAD_HEADER_SIZE && js_shell_payload_header[offset] != 0u) offset++;
    if (offset >= JS_SHELL_PAYLOAD_HEADER_SIZE ||
        offset != sizeof(JS_NATIVE_MAX_PAYLOAD_MARKER) - 1u ||
        memcmp(js_shell_payload_header, JS_NATIVE_MAX_PAYLOAD_MARKER, offset) != 0 ||
        g_js_shell_stub_marker[0] != 'A') goto fail;
    offset++;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &version) ||
        !js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &level) ||
        !js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &nonce_size)) goto fail;
    if (version != JS_SHELL_PROTOCOL_VERSION || level != JS_SHELL_PROTOCOL_LEVEL ||
        (level != 2u && level != 3u) || nonce_size != 16u || offset > JS_SHELL_PAYLOAD_HEADER_SIZE ||
        JS_SHELL_PAYLOAD_HEADER_SIZE - offset < 16u) goto fail;
    memcpy(meta->nonce, js_shell_payload_header + offset, 16u);
    offset += 16u;
    if (!js_shell_read_u32_le(js_shell_payload_header, JS_SHELL_PAYLOAD_HEADER_SIZE, &offset, &metadata_size) ||
        metadata_size == 0u || offset > JS_SHELL_PAYLOAD_HEADER_SIZE ||
        (size_t)metadata_size != JS_SHELL_PAYLOAD_HEADER_SIZE - offset) goto fail;
    metadata = js_shell_payload_header + offset;

    if (!js_shell_skip_string(metadata, (size_t)metadata_size, &metadata_offset) ||
        !js_shell_skip_string(metadata, (size_t)metadata_size, &metadata_offset) ||
        !js_shell_skip_string(metadata, (size_t)metadata_size, &metadata_offset) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->original_size) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->stored_size) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->encoded_size) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->compression_codec) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->chunk_size) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->chunk_count) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->layout_profile) ||
        !js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &meta->dispatcher_profile)) goto fail;
    if (metadata_offset > (size_t)metadata_size || (size_t)metadata_size - metadata_offset < 64u) goto fail;
    memcpy(meta->section_digest_hmac, metadata + metadata_offset, 32u);
    metadata_offset += 32u;
    memcpy(meta->binding_tag, metadata + metadata_offset, 32u);
    metadata_offset += 32u;
    if (!js_shell_read_u32_le(metadata, (size_t)metadata_size, &metadata_offset, &chunk_tags_size) ||
        meta->chunk_count > UINT32_MAX / 32u || chunk_tags_size != meta->chunk_count * 32u ||
        metadata_offset > (size_t)metadata_size || (size_t)chunk_tags_size != (size_t)metadata_size - metadata_offset) goto fail;
    meta->chunk_tags = metadata + metadata_offset;
    meta->chunk_tags_size = (size_t)chunk_tags_size;

    if (meta->original_size == 0u || meta->stored_size == 0u || meta->stored_size != meta->encoded_size ||
        meta->encoded_size != JS_SHELL_PAYLOAD_SIZE ||
        (meta->compression_codec != JS_SHELL_COMPRESSION_NONE && meta->compression_codec != JS_SHELL_COMPRESSION_ZSTD) ||
        meta->chunk_size == 0u || meta->chunk_count != 1u + (meta->encoded_size - 1u) / meta->chunk_size) goto fail;
    {
        unsigned int binding_acc = 0u;
        for (size_t index = 0u; index < sizeof(meta->binding_tag); index++) binding_acc |= (unsigned int)meta->binding_tag[index];
        if (binding_acc == 0u) goto fail;
    }
    js_shell_kdf(
        binding_salt,
        "javashroud-aken-v4-native-shell-stream-v1",
        meta->nonce,
        meta->binding_tag,
        0u,
        stream_key
    );
    return 1;

fail:
    js_shell_secure_wipe(stream_key, 32u);
    memset(meta, 0, sizeof(*meta));
    return 0;
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
    static const unsigned char domain[] = "javashroud-aken-v4-native-shell-inner-digest-v1";
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
        (const void *)abi->native_decrypt_class_bytes,
        (const void *)abi->native_sealed_binding_key,
        (const void *)abi->native_decode_runtime_resource,
        (const void *)abi->execute_vm_resource,
        (const void *)abi->execute_vm_resource_by_token,
        (const void *)abi->execute_vm_resource_void,
        (const void *)abi->execute_vm_resource_int,
        (const void *)abi->execute_vm_resource_int_int,
        (const void *)abi->execute_vm_resource_int_void,
        (const void *)abi->execute_aken_vm_page,
        (const void *)abi->decode_aken_string_page,
        (const void *)abi->read_aken_class_page,
        (const void *)abi->map_aken_native_chunk,
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

static void js_shell_native_install_boot_envelope_name(char out[26]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Install", 7u);
    memcpy(out + 13u, "BootEnvelope", 13u);
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

static void js_shell_native_class_decrypt_name(char out[24]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Decrypt", 7u);
    memcpy(out + 13u, "Class", 5u);
    memcpy(out + 18u, "Bytes", 6u);
}

static void js_shell_native_binding_key_name(char out[23]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Sealed", 6u);
    memcpy(out + 12u, "Binding", 7u);
    memcpy(out + 19u, "Key", 4u);
}

static void js_shell_native_decode_resource_name(char out[28]) {
    memcpy(out, "native", 6u);
    memcpy(out + 6u, "Decode", 6u);
    memcpy(out + 12u, "Runtime", 7u);
    memcpy(out + 19u, "Resource", 9u);
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

/* The helper ABI still exposes this slot while the Java-side migration removes
 * the declaration. AKEN v4 deliberately refuses all legacy envelope handoffs;
 * startup never calls this function and no boot parsing or key delivery remains
 * in the native shell. */
static jboolean JNICALL js_shell_native_install_boot_envelope(
    JNIEnv *env,
    jclass cls,
    jbyteArray envelope_array,
    jbyteArray sidecar_array) {
    (void)env;
    (void)cls;
    (void)envelope_array;
    (void)sidecar_array;
    return JNI_FALSE;
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

static jbyteArray JNICALL js_shell_native_decrypt_class_bytes(
    JNIEnv *env,
    jclass cls,
    jbyteArray keyIdArr,
    jbyteArray saltArr,
    jbyteArray nonceArr,
    jbyteArray ciphertextArr,
    jbyteArray aadArr,
    jint keyLength
) {
    JNIEnv *call_env = js_shell_current_env_for("native-decrypt-class-bytes", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->native_decrypt_class_bytes) return 0;
    return g_inner_abi->native_decrypt_class_bytes(
        call_env,
        js_shell_effective_helper_class(cls),
        keyIdArr,
        saltArr,
        nonceArr,
        ciphertextArr,
        aadArr,
        keyLength);
}

static jstring JNICALL js_shell_native_sealed_binding_key(JNIEnv *env, jclass cls, jbyteArray valueArr) {
    JNIEnv *call_env = js_shell_current_env_for("native-sealed-binding-key", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->native_sealed_binding_key) return 0;
    return g_inner_abi->native_sealed_binding_key(
        call_env,
        js_shell_effective_helper_class(cls),
        valueArr);
}

static jbyteArray JNICALL js_shell_native_decode_runtime_resource(JNIEnv *env, jclass cls, jbyteArray encoded) {
    JNIEnv *call_env = js_shell_current_env_for("native-decode-runtime-resource", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->native_decode_runtime_resource) return 0;
    return g_inner_abi->native_decode_runtime_resource(
        call_env,
        js_shell_effective_helper_class(cls),
        encoded);
}

static jobject JNICALL js_shell_execute_aken_vm_page(JNIEnv *env, jclass cls, jlong entryToken, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof, jobjectArray args) {
    JNIEnv *call_env = js_shell_current_env_for("execute-aken-vm-page", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->execute_aken_vm_page) return 0;
    return g_inner_abi->execute_aken_vm_page(call_env, js_shell_effective_helper_class(cls), entryToken, encodedHandle, pageIndex, callSiteProof, args);
}

static jbyteArray JNICALL js_shell_decode_aken_string_page(JNIEnv *env, jclass cls, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof) {
    JNIEnv *call_env = js_shell_current_env_for("decode-aken-string-page", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->decode_aken_string_page) return 0;
    return g_inner_abi->decode_aken_string_page(call_env, js_shell_effective_helper_class(cls), encodedHandle, pageIndex, callSiteProof);
}

static jbyteArray JNICALL js_shell_read_aken_class_page(JNIEnv *env, jclass cls, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof) {
    JNIEnv *call_env = js_shell_current_env_for("read-aken-class-page", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->read_aken_class_page) return 0;
    return g_inner_abi->read_aken_class_page(call_env, js_shell_effective_helper_class(cls), encodedHandle, pageIndex, callSiteProof);
}

static jbyteArray JNICALL js_shell_map_aken_native_chunk(JNIEnv *env, jclass cls, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof) {
    JNIEnv *call_env = js_shell_current_env_for("map-aken-native-chunk", env);
    if (!call_env || !g_inner_abi || !g_inner_abi->map_aken_native_chunk) return 0;
    return g_inner_abi->map_aken_native_chunk(call_env, js_shell_effective_helper_class(cls), encodedHandle, pageIndex, callSiteProof);
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
    char *mapped_install_boot = 0, *mapped_install_boot_envelope = 0, *mapped_boot_ready = 0, *mapped_abort_boot = 0, *mapped_preload = 0, *mapped_decrypt_aes = 0, *mapped_class_key = 0, *mapped_class_decrypt = 0, *mapped_binding_key = 0, *mapped_decode_resource = 0;
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
    char native_install_boot_envelope_name[26];
    char native_boot_ready_name[26];
    char native_abort_boot_name[24];
    char native_preload_name[30];
    char native_decrypt_aes_name[17];
    char native_class_key_name[31];
    char native_class_decrypt_name[24];
    char native_binding_key_name[23];
    char native_decode_resource_name[28];
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
    js_shell_native_install_boot_envelope_name(native_install_boot_envelope_name);
    js_shell_native_boot_ready_name(native_boot_ready_name);
    js_shell_native_abort_boot_name(native_abort_boot_name);
    js_shell_native_preload_name(native_preload_name);
    js_shell_native_decrypt_aes_name(native_decrypt_aes_name);
    js_shell_native_class_key_name(native_class_key_name);
    js_shell_native_class_decrypt_name(native_class_decrypt_name);
    js_shell_native_binding_key_name(native_binding_key_name);
    js_shell_native_decode_resource_name(native_decode_resource_name);
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
    mapped_install_boot_envelope = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_install_boot_envelope_name, "([B[B)Z") : 0;
    mapped_boot_ready = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_boot_ready_name, "()Z") : 0;
    mapped_abort_boot = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_abort_boot_name, "()V") : 0;
    mapped_preload = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_preload_name, "([B[B[B)V") : 0;
    mapped_decrypt_aes = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_decrypt_aes_name, "([B[B[B)[B") : 0;
    mapped_class_key = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_class_key_name, "([B[BI)[B") : 0;
    mapped_class_decrypt = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_class_decrypt_name, "([B[B[B[B[BI)[B") : 0;
    mapped_binding_key = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_binding_key_name, "([B)Ljava/lang/String;") : 0;
    mapped_decode_resource = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_decode_resource_name, "([B)[B") : 0;
    mapped_exec = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_exec_name, "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;") : 0;
    mapped_exec_token = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_exec_token_name, "(J[Ljava/lang/Object;)Ljava/lang/Object;") : 0;
    mapped_void = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_void_name, "(J)V") : 0;
    mapped_int = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_name, "(J)I") : 0;
    mapped_int_int = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_int_name, "(JI)I") : 0;
    mapped_int_void = original_owner ? js_shell_lookup_bound_method(env, original_owner, native_int_void_name, "(JI)V") : 0;
    JNINativeMethod methods[25];
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
    methods[11].name = (char *)((mapped_class_decrypt && mapped_class_decrypt[0]) ? mapped_class_decrypt : native_class_decrypt_name);
    methods[11].signature = "([B[B[B[B[BI)[B";
    methods[11].fnPtr = (void *)js_shell_native_decrypt_class_bytes;
    methods[12].name = (char *)((mapped_exec && mapped_exec[0]) ? mapped_exec : native_exec_name);
    methods[12].signature = "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[12].fnPtr = (void *)js_shell_execute_vm_resource;
    methods[13].name = (char *)((mapped_exec_token && mapped_exec_token[0]) ? mapped_exec_token : native_exec_token_name);
    methods[13].signature = "(J[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[13].fnPtr = (void *)js_shell_execute_vm_resource_by_token;
    methods[14].name = (char *)((mapped_void && mapped_void[0]) ? mapped_void : native_void_name);
    methods[14].signature = "(J)V";
    methods[14].fnPtr = (void *)js_shell_execute_vm_resource_void;
    methods[15].name = (char *)((mapped_int_void && mapped_int_void[0]) ? mapped_int_void : native_int_void_name);
    methods[15].signature = "(JI)V";
    methods[15].fnPtr = (void *)js_shell_execute_vm_resource_int_void;
    methods[16].name = (char *)((mapped_int && mapped_int[0]) ? mapped_int : native_int_name);
    methods[16].signature = "(J)I";
    methods[16].fnPtr = (void *)js_shell_execute_vm_resource_int;
    methods[17].name = (char *)((mapped_int_int && mapped_int_int[0]) ? mapped_int_int : native_int_int_name);
    methods[17].signature = "(JI)I";
    methods[17].fnPtr = (void *)js_shell_execute_vm_resource_int_int;
    methods[18].name = (char *)((mapped_install_boot_envelope && mapped_install_boot_envelope[0]) ? mapped_install_boot_envelope : native_install_boot_envelope_name);
    methods[18].signature = "([B[B)Z";
    methods[18].fnPtr = (void *)js_shell_native_install_boot_envelope;
    methods[19].name = (char *)((mapped_decode_resource && mapped_decode_resource[0]) ? mapped_decode_resource : native_decode_resource_name);
    methods[19].signature = "([B)[B";
    methods[19].fnPtr = (void *)js_shell_native_decode_runtime_resource;
    methods[20].name = (char *)((mapped_binding_key && mapped_binding_key[0]) ? mapped_binding_key : native_binding_key_name);
    methods[20].signature = "([B)Ljava/lang/String;";
    methods[20].fnPtr = (void *)js_shell_native_sealed_binding_key;
    methods[21].name = "nativeExecuteAkenVmPage";
    methods[21].signature = "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[21].fnPtr = (void *)js_shell_execute_aken_vm_page;
    methods[22].name = "nativeDecodeAkenStringPage";
    methods[22].signature = "([BI[B)[B";
    methods[22].fnPtr = (void *)js_shell_decode_aken_string_page;
    methods[23].name = "nativeReadAkenClassPage";
    methods[23].signature = "([BI[B)[B";
    methods[23].fnPtr = (void *)js_shell_read_aken_class_page;
    methods[24].name = "nativeMapAkenNativeChunk";
    methods[24].signature = "([BI[B)[B";
    methods[24].fnPtr = (void *)js_shell_map_aken_native_chunk;
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
    free(mapped_install_boot_envelope);
    free(mapped_boot_ready);
    free(mapped_abort_boot);
    free(mapped_preload);
    free(mapped_decrypt_aes);
    free(mapped_class_key);
    free(mapped_class_decrypt);
    free(mapped_binding_key);
    free(mapped_decode_resource);
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
    unsigned char binding_salt[32];
    js_shell_payload_view view;
    JNIEnv *env = 0;
    memset(&view, 0, sizeof(view));
    memset(&meta, 0, sizeof(meta));
    memset(stream_key, 0, sizeof(stream_key));
    memset(binding_salt, 0, sizeof(binding_salt));

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env ||
        !js_shell_reconstruct_aken_binding_salt(binding_salt) ||
        !js_shell_verify_aken_payload_commitment(binding_salt) ||
        !js_shell_extract_aken_meta(&meta, stream_key, binding_salt)) {
        js_shell_secure_wipe(binding_salt, sizeof(binding_salt));
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        return js_shell_fail_onload();
    }
    js_shell_secure_wipe(binding_salt, sizeof(binding_salt));

    stored = js_shell_alloc((size_t)JS_SHELL_PAYLOAD_SIZE);
    if (!stored) {
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        return js_shell_fail_onload();
    }
    memcpy(stored, js_shell_payload_bytes, (size_t)JS_SHELL_PAYLOAD_SIZE);
    if (!js_shell_decode_payload_chunks(stored, (size_t)JS_SHELL_PAYLOAD_SIZE, stream_key, meta.nonce, meta.binding_tag, meta.chunk_size, meta.chunk_tags, meta.chunk_tags_size)) {
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        return js_shell_fail_onload();
    }
    if (meta.compression_codec == JS_SHELL_COMPRESSION_NONE) {
        if (meta.stored_size != meta.original_size || meta.stored_size != JS_SHELL_PAYLOAD_SIZE) {
            js_shell_secure_wipe(stream_key, sizeof(stream_key));
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
            js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
            return js_shell_fail_onload();
        }
        written = ZSTD_decompress(decoded, (size_t)meta.original_size, stored, (size_t)meta.stored_size);
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        stored = 0;
        if (ZSTD_isError(written) || written != (size_t)meta.original_size) {
            js_shell_secure_wipe(stream_key, sizeof(stream_key));
            js_shell_wipe_free(decoded, (size_t)meta.original_size);
            return js_shell_fail_onload();
        }
    } else {
        js_shell_wipe_free(stored, (size_t)JS_SHELL_PAYLOAD_SIZE);
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        return js_shell_fail_onload();
    }

    if (!js_shell_verify_inner_digest(stream_key, decoded, (size_t)meta.original_size, meta.section_digest_hmac)) {
        js_shell_secure_wipe(stream_key, sizeof(stream_key));
        js_shell_wipe_free(decoded, (size_t)meta.original_size);
        return js_shell_fail_onload();
    }
    js_shell_secure_wipe(stream_key, sizeof(stream_key));

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
    (void)reserved;
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
