#include "js_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int bytes_equal(const unsigned char *left, const unsigned char *right, size_t size) {
    unsigned char diff = 0u;
    if (!left || !right) return 0;
    for (size_t index = 0u; index < size; index++) diff |= (unsigned char)(left[index] ^ right[index]);
    return diff == 0u;
}

static uint64_t digest_bytes(const unsigned char *bytes, size_t size) {
    uint64_t digest = UINT64_C(1469598103934665603);
    if (!bytes && size != 0u) return 0u;
    for (size_t index = 0u; index < size; index++) {
        digest ^= (uint64_t)bytes[index];
        digest *= UINT64_C(1099511628211);
    }
    return digest;
}

static int all_zero(const unsigned char *bytes, size_t size) {
    unsigned char diff = 0u;
    if (!bytes && size != 0u) return 0;
    for (size_t index = 0u; index < size; index++) diff |= bytes[index];
    return diff == 0u;
}

static int check_gcm_vector(
    const char *name,
    const unsigned char *key,
    size_t key_size,
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_size,
    const unsigned char *ciphertext_and_tag,
    size_t ciphertext_and_tag_size,
    const unsigned char *expected_plaintext,
    size_t plaintext_size,
    uint64_t *digest
) {
    unsigned char plaintext[64];
    if (!name || !key || !nonce || !ciphertext_and_tag || plaintext_size > sizeof(plaintext) ||
        ciphertext_and_tag_size != plaintext_size + 16u) return 0;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (!js_aes_gcm_decrypt(key, key_size, nonce, aad, aad_size, ciphertext_and_tag,
            ciphertext_and_tag_size, plaintext)) {
        fprintf(stderr, "gcm valid vector failed: %s\n", name);
        js_vbc4_wipe_volatile(plaintext, sizeof(plaintext));
        return 0;
    }
    if (plaintext_size != 0u && !bytes_equal(plaintext, expected_plaintext, plaintext_size)) {
        fprintf(stderr, "gcm plaintext mismatch: %s\n", name);
        js_vbc4_wipe_volatile(plaintext, sizeof(plaintext));
        return 0;
    }
    if (digest) *digest ^= digest_bytes(plaintext, plaintext_size);
    js_vbc4_wipe_volatile(plaintext, sizeof(plaintext));
    return 1;
}

static int check_gcm_rejection(
    const char *name,
    const unsigned char *key,
    size_t key_size,
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_size,
    const unsigned char *ciphertext_and_tag,
    size_t ciphertext_and_tag_size,
    size_t plaintext_size
) {
    unsigned char altered[96];
    unsigned char plaintext[64];
    if (!name || !key || !nonce || !ciphertext_and_tag || ciphertext_and_tag_size > sizeof(altered) ||
        plaintext_size > sizeof(plaintext)) return 0;
    memcpy(altered, ciphertext_and_tag, ciphertext_and_tag_size);
    if (ciphertext_and_tag_size == 0u) return 0;
    altered[ciphertext_and_tag_size - 1u] ^= 0x80u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (js_aes_gcm_decrypt(key, key_size, nonce, aad, aad_size, altered,
            ciphertext_and_tag_size, plaintext)) {
        fprintf(stderr, "gcm rejection unexpectedly succeeded: %s\n", name);
        js_vbc4_wipe_volatile(plaintext, sizeof(plaintext));
        js_vbc4_wipe_volatile(altered, sizeof(altered));
        return 0;
    }
    if (plaintext_size != 0u && !all_zero(plaintext, plaintext_size)) {
        fprintf(stderr, "gcm rejection did not wipe output: %s\n", name);
        js_vbc4_wipe_volatile(plaintext, sizeof(plaintext));
        js_vbc4_wipe_volatile(altered, sizeof(altered));
        return 0;
    }
    js_vbc4_wipe_volatile(plaintext, sizeof(plaintext));
    js_vbc4_wipe_volatile(altered, sizeof(altered));
    return 1;
}

static int check_ctr_vector(
    const char *name,
    const unsigned char *key,
    size_t key_size,
    const unsigned char iv[16],
    const unsigned char *plaintext,
    const unsigned char *expected_ciphertext,
    size_t size,
    uint64_t *digest
) {
    unsigned char buffer[96];
    if (!name || !key || !iv || !plaintext || !expected_ciphertext || size > sizeof(buffer)) return 0;
    memcpy(buffer, plaintext, size);
    js_aes_ctr_xor(buffer, size, key, key_size, iv);
    if (!bytes_equal(buffer, expected_ciphertext, size)) {
        fprintf(stderr, "ctr known-answer mismatch: %s\n", name);
        js_vbc4_wipe_volatile(buffer, sizeof(buffer));
        return 0;
    }
    if (digest) *digest ^= digest_bytes(buffer, size);
    js_aes_ctr_xor(buffer, size, key, key_size, iv);
    if (!bytes_equal(buffer, plaintext, size)) {
        fprintf(stderr, "ctr round-trip mismatch: %s\n", name);
        js_vbc4_wipe_volatile(buffer, sizeof(buffer));
        return 0;
    }
    js_vbc4_wipe_volatile(buffer, sizeof(buffer));
    return 1;
}

static int check_ctr_boundaries(const unsigned char key[16], const unsigned char iv[16], uint64_t *digest) {
    static const size_t sizes[] = {0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 4096u};
    unsigned char input[4096];
    unsigned char expected[4096];
    unsigned char roundtrip[4096];
    for (size_t index = 0u; index < sizeof(input); index++) input[index] = (unsigned char)(index * 13u + 7u);
    for (size_t size_index = 0u; size_index < sizeof(sizes) / sizeof(sizes[0]); size_index++) {
        size_t size = sizes[size_index];
        memcpy(expected, input, size);
        memcpy(roundtrip, input, size);
        js_aes_ctr_xor(expected, size, key, 16u, iv);
        js_aes_ctr_xor(roundtrip, size, key, 16u, iv);
        js_aes_ctr_xor(roundtrip, size, key, 16u, iv);
        if (!bytes_equal(roundtrip, input, size)) {
            fprintf(stderr, "ctr boundary round-trip mismatch: size=%zu\n", size);
            js_vbc4_wipe_volatile(input, sizeof(input));
            js_vbc4_wipe_volatile(expected, sizeof(expected));
            js_vbc4_wipe_volatile(roundtrip, sizeof(roundtrip));
            return 0;
        }
        if (digest) *digest ^= digest_bytes(expected, size);
    }
    js_vbc4_wipe_volatile(input, sizeof(input));
    js_vbc4_wipe_volatile(expected, sizeof(expected));
    js_vbc4_wipe_volatile(roundtrip, sizeof(roundtrip));
    return 1;
}

int main(void) {
    static const unsigned char zero_key_128[16] = {0};
    static const unsigned char zero_key_256[32] = {0};
    static const unsigned char zero_nonce[12] = {0};
    static const unsigned char gcm128_empty[16] = {
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
    };
    static const unsigned char gcm256_empty[16] = {
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
    };
    static const unsigned char gcm128_partial[53] = {
        0x02, 0x8a, 0xd9, 0xca, 0x65, 0xb0, 0xa4, 0x9a, 0xfa, 0x22, 0xc9, 0xb5, 0x7c, 0xbc, 0xf1, 0x68,
        0xe6, 0x87, 0xb9, 0xbf, 0x5c, 0x5d, 0x4e, 0x3b, 0xee, 0xe7, 0x92, 0xe3, 0x89, 0x95, 0xde, 0xc0,
        0x01, 0x20, 0x32, 0x05, 0x6b, 0xf3, 0x52, 0xf5, 0x2c, 0x34, 0x1d, 0x8a, 0x79, 0x8f, 0x72, 0xba,
        0xdc, 0xb3, 0xc7, 0x05, 0xa3,
    };
    static const unsigned char gcm128_aad[] = "JavaShroud-AAD";
    static const unsigned char gcm128_plain[37] = {
        1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u, 19u,
        20u, 21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 32u, 33u, 34u, 35u, 36u, 37u,
    };
    static const unsigned char gcm256_partial[45] = {
        0x08, 0x4a, 0xb1, 0xd1, 0x84, 0x78, 0x09, 0x7e, 0x4a, 0xf1, 0xd8, 0x6e, 0x71, 0x8e, 0x50, 0x83,
        0xc4, 0xfd, 0x3a, 0x09, 0x2b, 0x08, 0x19, 0x61, 0x57, 0x52, 0x7e, 0x90, 0x11, 0xb1, 0xab, 0xfb,
        0xd8, 0x4c, 0x23, 0x9a, 0x64, 0x08, 0x3e, 0xcf, 0x66, 0x83, 0xb9, 0xc6, 0x2e,
    };
    static const unsigned char gcm256_nonce[12] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u};
    static const unsigned char gcm256_aad[12] = {0xa0u, 0xa1u, 0xa2u, 0xa3u, 0xa4u, 0xa5u, 0xa6u, 0xa7u, 0xa8u, 0xa9u, 0xaau, 0xabu};
    static const unsigned char gcm256_plain[29] = {
        0x80u, 0x81u, 0x82u, 0x83u, 0x84u, 0x85u, 0x86u, 0x87u, 0x88u, 0x89u, 0x8au, 0x8bu, 0x8cu, 0x8du,
        0x8eu, 0x8fu, 0x90u, 0x91u, 0x92u, 0x93u, 0x94u, 0x95u, 0x96u, 0x97u, 0x98u, 0x99u, 0x9au, 0x9bu, 0x9cu,
    };
    static const unsigned char ctr_key_128[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    static const unsigned char ctr_key_256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    static const unsigned char ctr_iv[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    static const unsigned char ctr_plain[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    static const unsigned char ctr128_expected[64] = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
    };
    static const unsigned char ctr256_expected[64] = {
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
    };
    static const unsigned char block_input[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };
    static const unsigned char block_expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    };
    unsigned char block_output[16];
    uint64_t output_digest = UINT64_C(0x6a09e667f3bcc909);
    js_crypto_runtime_metrics metrics;
    int hardware_available;
    int ghash_hardware_available;

    js_crypto_runtime_metrics_reset();
    js_aes128_encrypt_block(block_input, ctr_key_128, block_output);
    if (!bytes_equal(block_output, block_expected, sizeof(block_output))) return 1;
    output_digest ^= digest_bytes(block_output, sizeof(block_output));
    if (!check_gcm_vector("gcm128-empty", zero_key_128, sizeof(zero_key_128), zero_nonce, NULL, 0u,
            gcm128_empty, sizeof(gcm128_empty), NULL, 0u, &output_digest) ||
        !check_gcm_vector("gcm256-empty", zero_key_256, sizeof(zero_key_256), zero_nonce, NULL, 0u,
            gcm256_empty, sizeof(gcm256_empty), NULL, 0u, &output_digest) ||
        !check_gcm_vector("gcm128-aad-partial", zero_key_128, sizeof(zero_key_128), zero_nonce, gcm128_aad, sizeof(gcm128_aad) - 1u,
            gcm128_partial, sizeof(gcm128_partial), gcm128_plain, sizeof(gcm128_plain), &output_digest) ||
        !check_gcm_vector("gcm256-aad-partial", zero_key_256, sizeof(zero_key_256), gcm256_nonce, gcm256_aad, sizeof(gcm256_aad),
            gcm256_partial, sizeof(gcm256_partial), gcm256_plain, sizeof(gcm256_plain), &output_digest)) return 1;
    if (!check_gcm_rejection("wrong-tag", zero_key_128, sizeof(zero_key_128), zero_nonce, gcm128_aad, sizeof(gcm128_aad) - 1u,
            gcm128_partial, sizeof(gcm128_partial), sizeof(gcm128_plain)) ||
        !check_gcm_rejection("wrong-key", ctr_key_128, sizeof(ctr_key_128), zero_nonce, gcm128_aad, sizeof(gcm128_aad) - 1u,
            gcm128_partial, sizeof(gcm128_partial), sizeof(gcm128_plain)) ||
        !check_gcm_rejection("wrong-nonce", zero_key_128, sizeof(zero_key_128), ctr_iv, gcm128_aad, sizeof(gcm128_aad) - 1u,
            gcm128_partial, sizeof(gcm128_partial), sizeof(gcm128_plain)) ||
        !check_gcm_rejection("wrong-aad", zero_key_128, sizeof(zero_key_128), zero_nonce, gcm256_aad, sizeof(gcm256_aad),
            gcm128_partial, sizeof(gcm128_partial), sizeof(gcm128_plain))) return 1;
    {
        unsigned char truncated[15] = {0};
        unsigned char output[16];
        memset(output, 0xa5, sizeof(output));
        if (js_aes_gcm_decrypt(zero_key_128, sizeof(zero_key_128), zero_nonce, NULL, 0u, truncated, sizeof(truncated), output)) return 1;
        js_vbc4_wipe_volatile(output, sizeof(output));
    }
    if (!check_ctr_vector("ctr128", ctr_key_128, sizeof(ctr_key_128), ctr_iv, ctr_plain, ctr128_expected, sizeof(ctr_plain), &output_digest) ||
        !check_ctr_vector("ctr256", ctr_key_256, sizeof(ctr_key_256), ctr_iv, ctr_plain, ctr256_expected, sizeof(ctr_plain), &output_digest) ||
        !check_ctr_boundaries(ctr_key_128, ctr_iv, &output_digest)) return 1;
    js_crypto_runtime_metrics_snapshot(&metrics);
    hardware_available = js_aes_hardware_available();
    ghash_hardware_available = js_ghash_hardware_available();
    if (metrics.auth_failure_count < 4u || metrics.wipe_count == 0u || metrics.aes_block_count == 0u ||
        metrics.ghash_block_count == 0u || metrics.security_checks_skipped != 0u || metrics.fallback_count != 0u ||
        metrics.legacy_path_hits != 0u || metrics.plaintext_persistence_bytes != 0u || metrics.wipe_failure_count != 0u) return 1;
    printf("crypto_kat_security_probe status=pass hardware_crypto_path=%llu software_crypto_path=%llu hardware_available=%d ghash_hardware_available=%d aes_block_count=%llu ghash_block_count=%llu auth_failure_count=%llu wipe_count=%llu security_checks_skipped=%llu fallback_count=%llu legacy_path_hits=%llu plaintext_persistence_bytes=%llu output_digest=%016llx\n",
        (unsigned long long)metrics.hardware_crypto_path,
        (unsigned long long)metrics.software_crypto_path,
        hardware_available,
        ghash_hardware_available,
        (unsigned long long)metrics.aes_block_count,
        (unsigned long long)metrics.ghash_block_count,
        (unsigned long long)metrics.auth_failure_count,
        (unsigned long long)metrics.wipe_count,
        (unsigned long long)metrics.security_checks_skipped,
        (unsigned long long)metrics.fallback_count,
        (unsigned long long)metrics.legacy_path_hits,
        (unsigned long long)metrics.plaintext_persistence_bytes,
        (unsigned long long)output_digest);
    js_vbc4_wipe_volatile(block_output, sizeof(block_output));
    return 0;
}
