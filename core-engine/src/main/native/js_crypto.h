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
JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);
JS_HIDDEN void js_aes128_encrypt_block(const unsigned char in[16], const unsigned char key[16], unsigned char out[16]);
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
