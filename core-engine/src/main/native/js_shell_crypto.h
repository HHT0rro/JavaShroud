#ifndef JS_SHELL_CRYPTO_H
#define JS_SHELL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef struct js_shell_sha256_ctx {
    unsigned char data[64];
    size_t data_len;
    uint64_t bit_len;
    uint32_t state[8];
} js_shell_sha256_ctx;

int js_shell_consttime_equal(const unsigned char *a, const unsigned char *b, size_t len);
void js_shell_secure_wipe(void *bytes, size_t size);
void js_shell_sha256_init(js_shell_sha256_ctx *ctx);
void js_shell_sha256_update(js_shell_sha256_ctx *ctx, const unsigned char *data, size_t len);
void js_shell_sha256_final(js_shell_sha256_ctx *ctx, unsigned char out[32]);
void js_shell_hmac_sha256(const unsigned char *key, size_t key_size, const unsigned char *data, size_t data_size, unsigned char out[32]);
void js_shell_kdf(const unsigned char key[32], const char *domain, const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int value, unsigned char out[32]);
void js_shell_aes128_ctr_xor(unsigned char *bytes, size_t size, const unsigned char key[16], const unsigned char iv[16]);
void js_shell_derive_stream_key(const unsigned char seed[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned char out[32]);
int js_shell_open_seed_envelope(const unsigned char boot_secret[32], const unsigned char seed_nonce[16], const unsigned char encrypted_seed[32], const unsigned char seed_tag[32], unsigned char seed_out[32]);
int js_shell_open_sensitive_header(const unsigned char seed[32], const unsigned char nonce[16], const unsigned char *encrypted_header, size_t header_size, const unsigned char header_tag[32], unsigned char *plain_out);
int js_shell_decode_payload_chunks(unsigned char *bytes, size_t size, const unsigned char stream_key[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int chunk_size, const unsigned char *chunk_tags, size_t chunk_tags_size);

#endif
