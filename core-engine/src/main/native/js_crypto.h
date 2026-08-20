#ifndef JS_CRYPTO_H
#define JS_CRYPTO_H

#include "js_native_common.h"

typedef struct {
    unsigned char data[64];
    uint32_t data_len;
    uint64_t bit_len;
    uint32_t state[8];
} js_sha256_ctx;

JS_HIDDEN void js_sha256_init(js_sha256_ctx *ctx);
JS_HIDDEN void js_sha256_update(js_sha256_ctx *ctx, const unsigned char *data, int len);
JS_HIDDEN void js_sha256_final(js_sha256_ctx *ctx, unsigned char hash[32]);
typedef struct {
    uint64_t hardware_crypto_path;
    uint64_t software_crypto_path;
    uint64_t aes_block_count;
    uint64_t ghash_block_count;
    uint64_t vm_frame_reuse_count;
    uint64_t vm_heap_fallback_count;
    uint64_t resource_index_hit_count;
    uint64_t decompress_context_reuse_count;
    uint64_t jni_cache_hit_count;
    uint64_t auth_check_count;
    uint64_t auth_failure_count;
    uint64_t digest_check_count;
    uint64_t tag_check_count;
    uint64_t length_check_count;
    uint64_t structure_check_count;
    uint64_t jni_abi_check_count;
    uint64_t wipe_count;
    uint64_t wipe_failure_count;
    uint64_t plaintext_persistence_bytes;
    uint64_t fallback_count;
    uint64_t legacy_path_hits;
    uint64_t exception_count;
    uint64_t security_checks_skipped;
    uint64_t phase_p50;
    uint64_t phase_p95;
    uint64_t phase_max;
} js_crypto_runtime_metrics;

/* Public snapshot transport used by the runtime benchmark/telemetry fixture.
 * Runtime storage is synchronized internally; this plain layout deliberately
 * contains counters only, never a key, nonce, plaintext, descriptor secret,
 * source path, or exception payload. */
typedef js_crypto_runtime_metrics NativeRuntimeMetrics;
typedef js_crypto_runtime_metrics CryptoRuntimeMetrics;
typedef js_crypto_runtime_metrics VmRuntimeMetrics;
typedef js_crypto_runtime_metrics ResourceRuntimeMetrics;
typedef js_crypto_runtime_metrics RuntimeSecurityCounters;

JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);
JS_HIDDEN void js_crypto_runtime_metrics_reset(void);
JS_HIDDEN void js_crypto_runtime_metrics_snapshot(js_crypto_runtime_metrics *out);
JS_HIDDEN void js_aes128_encrypt_block(const unsigned char in[16], const unsigned char key[16], unsigned char out[16]);
JS_HIDDEN void js_aes_ctr_xor(unsigned char *bytes, size_t size, const unsigned char *key, size_t key_len, const unsigned char iv[16]);
JS_HIDDEN void js_aes128_ctr_xor(unsigned char *bytes, size_t size, const unsigned char key[16], const unsigned char iv[16]);
JS_HIDDEN int js_aes_hardware_available(void);
JS_HIDDEN int js_ghash_hardware_available(void);

/* Low-overhead counter hooks used by VM/resource/JNI hot paths. */
JS_HIDDEN void js_runtime_metrics_note_vm_frame_reuse(void);
JS_HIDDEN void js_runtime_metrics_note_vm_heap_fallback(void);
JS_HIDDEN void js_runtime_metrics_note_resource_index_hit(void);
JS_HIDDEN void js_runtime_metrics_note_decompress_context_reuse(void);
JS_HIDDEN void js_runtime_metrics_note_jni_cache_hit(void);
JS_HIDDEN void js_runtime_metrics_note_auth_check(void);
JS_HIDDEN void js_runtime_metrics_note_auth_failure(void);
JS_HIDDEN void js_runtime_metrics_note_digest_check(void);
JS_HIDDEN void js_runtime_metrics_note_tag_check(void);
JS_HIDDEN void js_runtime_metrics_note_length_check(void);
JS_HIDDEN void js_runtime_metrics_note_structure_check(void);
JS_HIDDEN void js_runtime_metrics_note_jni_abi_check(void);
JS_HIDDEN void js_runtime_metrics_note_fallback(void);
JS_HIDDEN void js_runtime_metrics_note_exception(void);

/*
 * Eight scalar AES-256 key lanes used only by the AKEN page-bound terminal.
 * This is deliberately not a byte-array or aggregate-key ABI.  The lanes are
 * passed as independent scalar arguments and are only available inside one
 * verified page-open scope.
 */
JS_HIDDEN int js_aes_gcm_decrypt_lanes(
    uint32_t lane0,
    uint32_t lane1,
    uint32_t lane2,
    uint32_t lane3,
    uint32_t lane4,
    uint32_t lane5,
    uint32_t lane6,
    uint32_t lane7,
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *ciphertext_and_tag,
    size_t ciphertext_and_tag_len,
    unsigned char *plain_out
);

/* Authenticated AES-GCM decrypt for 96-bit nonces and a 128-bit tag. The
 * plaintext buffer is wiped when authentication fails. key_len is 16 or 32. */
JS_HIDDEN int js_aes_gcm_decrypt(
    const unsigned char *key,
    size_t key_len,
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *ciphertext_and_tag,
    size_t ciphertext_and_tag_len,
    unsigned char *plain_out
);
JS_HIDDEN void js_ctr_inc(unsigned char counter[16]);
JS_HIDDEN void js_vbc4_decrypt_block(unsigned char *buf, int len, int seed, const unsigned char nonce[16], int section, int block_id);
JS_HIDDEN void js_vbc4_decrypt_block_with_material(unsigned char *buf, int len, const unsigned char key[16], const unsigned char iv[16]);

#endif
