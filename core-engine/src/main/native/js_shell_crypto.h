#ifndef JS_SHELL_CRYPTO_H
#define JS_SHELL_CRYPTO_H

#include <stddef.h>

int js_shell_consttime_equal(const unsigned char *a, const unsigned char *b, size_t len);
void js_shell_secure_wipe(void *bytes, size_t size);
void js_shell_mac32(const unsigned char *key, size_t key_size, const unsigned char *header, size_t header_size, const unsigned char *payload, size_t payload_size, const unsigned char *binding_tag, size_t binding_tag_size, unsigned char out[32]);
int js_shell_decode_payload_chunks(unsigned char *bytes, size_t size, const unsigned char *key, size_t key_size, const unsigned char nonce[16], unsigned int layout_profile, unsigned int dispatcher_profile, unsigned int chunk_size, const unsigned char *chunk_tags, size_t chunk_tags_size);

#endif
