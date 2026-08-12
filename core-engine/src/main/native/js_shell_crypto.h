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
/*
 * Opens an AES-256-GCM ciphertext encoded as ciphertext || 16-byte tag.
 * The nonce is restricted to the 96-bit form used by the JSBK sidecar.
 * Returns 1 only after authenticating the complete AAD and ciphertext; on
 * failure, the plaintext output range is wiped before returning 0.
 */
int js_shell_aes256_gcm_decrypt(
    const unsigned char key[32],
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_size,
    const unsigned char *ciphertext_and_tag,
    size_t ciphertext_and_tag_size,
    unsigned char *plain_out
);
/* Opens the canonical 118-byte JSBK v1 binary sidecar and returns its 32-byte KEK. */
int js_shell_open_boot_kek_sidecar(
    const unsigned char *sidecar,
    size_t sidecar_size,
    const unsigned char expected_binding[32],
    unsigned char kek_out[32]
);
void js_shell_derive_stream_key(const unsigned char seed[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned char out[32]);
int js_shell_open_seed_envelope(const unsigned char boot_secret[32], const unsigned char seed_nonce[16], const unsigned char encrypted_seed[32], const unsigned char seed_tag[32], unsigned char seed_out[32]);
int js_shell_open_sensitive_header(const unsigned char seed[32], const unsigned char nonce[16], const unsigned char *encrypted_header, size_t header_size, const unsigned char header_tag[32], unsigned char *plain_out);
int js_shell_decode_payload_chunks(unsigned char *bytes, size_t size, const unsigned char stream_key[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int chunk_size, const unsigned char *chunk_tags, size_t chunk_tags_size);

#endif
