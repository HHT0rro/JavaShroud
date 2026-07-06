#include "js_shell_crypto.h"

#include <stdint.h>
#include <string.h>

int js_shell_consttime_equal(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned int diff = 0;
    if (!a || !b) return 0;
    for (size_t i = 0; i < len; i++) diff |= (unsigned int)(a[i] ^ b[i]);
    return diff == 0;
}

static uint32_t js_shell_mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static uint32_t js_shell_seed32(const unsigned char *key, size_t key_size, const unsigned char nonce[16], unsigned int layout_profile, unsigned int dispatcher_profile) {
    uint32_t state = 0x6d617870u ^ (layout_profile * 0x45d9f3bu) ^ (dispatcher_profile * 0x119de1f3u);
    for (size_t i = 0; i < key_size; i++) state = js_shell_mix32(state ^ key[i] ^ (uint32_t)(i * 131u));
    for (int i = 0; i < 16; i++) state = js_shell_mix32(state ^ nonce[i] ^ (uint32_t)(i * 257u));
    return state;
}

static uint32_t js_shell_read_u32_le(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

void js_shell_mac32(const unsigned char *key, size_t key_size, const unsigned char *header, size_t header_size, const unsigned char *payload, size_t payload_size, const unsigned char *binding_tag, size_t binding_tag_size, unsigned char out[32]) {
    uint32_t state[8] = {
        0x4a534d32u, 0x9e3779b9u, 0x243f6a88u, 0xb7e15162u,
        0xdeadbeefu, 0x8badf00du, 0xc001d00du, 0x13579bdfu
    };
    const unsigned char *parts[4] = { key, header, payload, binding_tag };
    const size_t sizes[4] = { key_size, header_size, payload_size, binding_tag_size };
    for (int part = 0; part < 4; part++) {
        if (!parts[part] && sizes[part] != 0) return;
        for (size_t i = 0; i < sizes[part]; i++) {
            uint32_t v = (uint32_t)parts[part][i] + (uint32_t)(i * 17u) + (uint32_t)(part * 131u);
            state[(i + (size_t)part) & 7u] = js_shell_mix32(state[(i + (size_t)part) & 7u] ^ v ^ state[(i + 3u) & 7u]);
        }
    }
    for (int round = 0; round < 8; round++) {
        state[round] = js_shell_mix32(state[round] ^ state[(round + 1) & 7] ^ (uint32_t)(header_size + payload_size + binding_tag_size + key_size));
        out[round * 4 + 0] = (unsigned char)(state[round] & 0xffu);
        out[round * 4 + 1] = (unsigned char)((state[round] >> 8) & 0xffu);
        out[round * 4 + 2] = (unsigned char)((state[round] >> 16) & 0xffu);
        out[round * 4 + 3] = (unsigned char)((state[round] >> 24) & 0xffu);
    }
}

static uint32_t js_shell_chunk_tag32(const unsigned char *key, size_t key_size, const unsigned char nonce[16], unsigned int layout_profile, unsigned int dispatcher_profile, unsigned int chunk_index, const unsigned char *bytes, size_t length) {
    uint32_t state = js_shell_seed32(key, key_size, nonce, layout_profile, dispatcher_profile) ^ js_shell_mix32(chunk_index ^ (uint32_t)length);
    for (size_t i = 0; i < length; i++) {
        uint32_t value = (uint32_t)bytes[i] + (uint32_t)(i * 17u) + (uint32_t)(chunk_index * 131u);
        state = js_shell_mix32(state ^ value);
    }
    return js_shell_mix32(state ^ (uint32_t)length ^ (chunk_index * 0x9e3779b9u));
}

static void js_shell_decode_chunk(unsigned char *bytes, size_t length, const unsigned char *key, size_t key_size, const unsigned char nonce[16], unsigned int layout_profile, unsigned int dispatcher_profile, unsigned int chunk_index) {
    uint32_t state = js_shell_seed32(key, key_size, nonce, layout_profile, dispatcher_profile) ^ js_shell_mix32(chunk_index * 0x45d9f3bu);
    for (size_t i = 0; i < length; i++) {
        state = js_shell_mix32(state + (uint32_t)i + chunk_index * 0x119de1f3u + 0x9e3779b9u);
        bytes[i] = (unsigned char)(bytes[i] ^ (unsigned char)(state & 0xffu));
    }
}

int js_shell_decode_payload_chunks(unsigned char *bytes, size_t size, const unsigned char *key, size_t key_size, const unsigned char nonce[16], unsigned int layout_profile, unsigned int dispatcher_profile, unsigned int chunk_size, const unsigned char *chunk_tags, size_t chunk_tags_size) {
    if (!bytes || !key || !nonce || !chunk_tags || chunk_size == 0u) return 0;
    size_t chunk_count = size == 0u ? 0u : (size + (size_t)chunk_size - 1u) / (size_t)chunk_size;
    if (chunk_tags_size != chunk_count * 4u) return 0;
    for (size_t chunk_index = 0; chunk_index < chunk_count; chunk_index++) {
        size_t offset = chunk_index * (size_t)chunk_size;
        size_t length = size - offset;
        if (length > (size_t)chunk_size) length = (size_t)chunk_size;
        uint32_t actual = js_shell_chunk_tag32(key, key_size, nonce, layout_profile, dispatcher_profile, (unsigned int)chunk_index, bytes + offset, length);
        uint32_t expected = js_shell_read_u32_le(chunk_tags + chunk_index * 4u);
        if (actual != expected) return 0;
        js_shell_decode_chunk(bytes + offset, length, key, key_size, nonce, layout_profile, dispatcher_profile, (unsigned int)chunk_index);
    }
    return 1;
}
