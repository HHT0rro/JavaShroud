#include "js_shell_crypto.h"
#include "js_crypto.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

void js_shell_secure_wipe(void *bytes, size_t size) {
    /* Use the shared volatile wipe primitive so shell-only sensitive scratch
     * is covered by the same de-identified wipe accounting as native runtime
     * page, VM, and resource paths.  A null/zero request remains a no-op. */
    if (bytes && size) js_vbc4_wipe_volatile(bytes, size);
}

int js_shell_consttime_equal(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned int diff = 0;
    if (!a || !b) return 0;
    for (size_t i = 0; i < len; i++) diff |= (unsigned int)(a[i] ^ b[i]);
    return diff == 0;
}

static uint32_t js_shell_rotr32(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32u - bits));
}

static const uint32_t JS_SHELL_SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void js_shell_sha256_transform(js_shell_sha256_ctx *ctx, const unsigned char data[64]) {
    uint32_t words[64];
    for (unsigned int i = 0; i < 16u; i++) {
        words[i] = ((uint32_t)data[i * 4u] << 24) | ((uint32_t)data[i * 4u + 1u] << 16) |
            ((uint32_t)data[i * 4u + 2u] << 8) | (uint32_t)data[i * 4u + 3u];
    }
    for (unsigned int i = 16u; i < 64u; i++) {
        uint32_t s0 = js_shell_rotr32(words[i - 15u], 7u) ^ js_shell_rotr32(words[i - 15u], 18u) ^ (words[i - 15u] >> 3u);
        uint32_t s1 = js_shell_rotr32(words[i - 2u], 17u) ^ js_shell_rotr32(words[i - 2u], 19u) ^ (words[i - 2u] >> 10u);
        words[i] = words[i - 16u] + s0 + words[i - 7u] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (unsigned int i = 0; i < 64u; i++) {
        uint32_t s1 = js_shell_rotr32(e, 6u) ^ js_shell_rotr32(e, 11u) ^ js_shell_rotr32(e, 25u);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + choice + JS_SHELL_SHA256_K[i] + words[i];
        uint32_t s0 = js_shell_rotr32(a, 2u) ^ js_shell_rotr32(a, 13u) ^ js_shell_rotr32(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + s0 + majority;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
    js_shell_secure_wipe(words, sizeof(words));
}

void js_shell_sha256_init(js_shell_sha256_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u; ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu; ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
}

void js_shell_sha256_update(js_shell_sha256_ctx *ctx, const unsigned char *data, size_t len) {
    if (!ctx || (!data && len != 0u)) return;
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->data_len++] = data[i];
        if (ctx->data_len == 64u) {
            js_shell_sha256_transform(ctx, ctx->data);
            ctx->bit_len += 512u;
            ctx->data_len = 0u;
        }
    }
}

void js_shell_sha256_final(js_shell_sha256_ctx *ctx, unsigned char out[32]) {
    size_t index = ctx->data_len;
    ctx->data[index++] = 0x80u;
    if (index > 56u) {
        while (index < 64u) ctx->data[index++] = 0u;
        js_shell_sha256_transform(ctx, ctx->data);
        index = 0u;
    }
    while (index < 56u) ctx->data[index++] = 0u;
    ctx->bit_len += (uint64_t)ctx->data_len * 8u;
    for (unsigned int i = 0; i < 8u; i++) ctx->data[63u - i] = (unsigned char)(ctx->bit_len >> (i * 8u));
    js_shell_sha256_transform(ctx, ctx->data);
    for (unsigned int i = 0; i < 8u; i++) {
        out[i * 4u] = (unsigned char)(ctx->state[i] >> 24);
        out[i * 4u + 1u] = (unsigned char)(ctx->state[i] >> 16);
        out[i * 4u + 2u] = (unsigned char)(ctx->state[i] >> 8);
        out[i * 4u + 3u] = (unsigned char)ctx->state[i];
    }
    js_shell_secure_wipe(ctx, sizeof(*ctx));
}

void js_shell_hmac_sha256(const unsigned char *key, size_t key_size, const unsigned char *data, size_t data_size, unsigned char out[32]) {
    unsigned char normalized[64], inner[32];
    js_shell_sha256_ctx ctx;
    if (!out || (!key && key_size != 0u) || (!data && data_size != 0u)) return;
    memset(normalized, 0, sizeof(normalized));
    if (key_size > 64u) {
        js_shell_sha256_init(&ctx);
        js_shell_sha256_update(&ctx, key, key_size);
        js_shell_sha256_final(&ctx, normalized);
    } else if (key_size != 0u) {
        memcpy(normalized, key, key_size);
    }
    for (size_t i = 0; i < 64u; i++) normalized[i] ^= 0x36u;
    js_shell_sha256_init(&ctx);
    js_shell_sha256_update(&ctx, normalized, sizeof(normalized));
    js_shell_sha256_update(&ctx, data, data_size);
    js_shell_sha256_final(&ctx, inner);
    for (size_t i = 0; i < 64u; i++) normalized[i] ^= (unsigned char)(0x36u ^ 0x5cu);
    js_shell_sha256_init(&ctx);
    js_shell_sha256_update(&ctx, normalized, sizeof(normalized));
    js_shell_sha256_update(&ctx, inner, sizeof(inner));
    js_shell_sha256_final(&ctx, out);
    js_shell_secure_wipe(normalized, sizeof(normalized));
    js_shell_secure_wipe(inner, sizeof(inner));
}

void js_shell_kdf(const unsigned char key[32], const char *domain, const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int value, unsigned char out[32]) {
    unsigned char material[16 + 32 + 4 + 96];
    size_t domain_size;
    if (!key || !nonce || !binding_tag || !out) return;
    domain_size = domain ? strlen(domain) : 0u;
    if (domain_size > 96u) domain_size = 96u;
    memcpy(material, nonce, 16u);
    memcpy(material + 16u, binding_tag, 32u);
    material[48] = (unsigned char)(value >> 24);
    material[49] = (unsigned char)(value >> 16);
    material[50] = (unsigned char)(value >> 8);
    material[51] = (unsigned char)value;
    if (domain_size) memcpy(material + 52u, domain, domain_size);
    js_shell_hmac_sha256(key, 32u, material, 52u + domain_size, out);
    js_shell_secure_wipe(material, sizeof(material));
}

void js_shell_aes128_ctr_xor(unsigned char *bytes, size_t size, const unsigned char key[16], const unsigned char iv[16]) {
    js_aes128_ctr_xor(bytes, size, key, iv);
}

static int js_shell_decode_chunk(unsigned char *bytes, size_t length, const unsigned char stream_key[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int chunk_index, const unsigned char expected_tag[32]) {
    unsigned char chunk_key[32], tag_key[32], actual[32], iv_material[32];
    int ok = 0;
    js_shell_kdf(stream_key, "javashroud-aken-v4-native-shell-chunk-aes-v1", nonce, binding_tag, chunk_index, chunk_key);
    js_shell_kdf(stream_key, "javashroud-aken-v4-native-shell-chunk-hmac-v1", nonce, binding_tag, chunk_index, tag_key);
    js_shell_kdf(stream_key, "javashroud-aken-v4-native-shell-chunk-iv-v1", nonce, binding_tag, chunk_index, iv_material);
    js_shell_hmac_sha256(tag_key, sizeof(tag_key), bytes, length, actual);
    js_runtime_metrics_note_auth_check();
    js_runtime_metrics_note_tag_check();
    ok = js_shell_consttime_equal(actual, expected_tag, 32u);
    if (!ok) js_runtime_metrics_note_auth_failure();
    if (ok) js_shell_aes128_ctr_xor(bytes, length, chunk_key, iv_material);
    js_shell_secure_wipe(chunk_key,sizeof(chunk_key)); js_shell_secure_wipe(tag_key,sizeof(tag_key)); js_shell_secure_wipe(actual,sizeof(actual)); js_shell_secure_wipe(iv_material,sizeof(iv_material));
    return ok;
}

int js_shell_decode_payload_chunks(unsigned char *bytes, size_t size, const unsigned char stream_key[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int chunk_size, const unsigned char *chunk_tags, size_t chunk_tags_size) {
    size_t chunk_count, offset, length;
    /* Account for the real outer framing checks once per decode operation.
     * Per-chunk tag/auth counters stay in js_shell_decode_chunk so a rejected
     * payload still reports every tag actually verified before fail-closed
     * wiping. */
    js_runtime_metrics_note_structure_check();
    js_runtime_metrics_note_length_check();
    if (!bytes || !stream_key || !nonce || !binding_tag || !chunk_tags || chunk_size == 0u) {
        if (bytes && size) js_shell_secure_wipe(bytes, size);
        return 0;
    }
    chunk_count = size == 0u ? 0u : 1u + (size - 1u) / (size_t)chunk_size;
    if (chunk_count > (size_t)UINT_MAX ||
        chunk_count > SIZE_MAX / 32u ||
        chunk_tags_size != chunk_count * 32u) {
        /* No chunk has been authenticated yet, but the caller-provided
         * ciphertext is still sensitive runtime material.  Wipe it on every
         * framing/length rejection so malformed metadata cannot leave bytes
         * resident for a later mapping or loader path. */
        if (size) js_shell_secure_wipe(bytes, size);
        return 0;
    }
    for (size_t chunk_index=0u;chunk_index<chunk_count;chunk_index++) {
        offset=chunk_index*(size_t)chunk_size; length=size-offset;
        if(length>(size_t)chunk_size)length=(size_t)chunk_size;
        if(!js_shell_decode_chunk(bytes+offset,length,stream_key,nonce,binding_tag,(unsigned int)chunk_index,chunk_tags+chunk_index*32u)) {
            js_shell_secure_wipe(bytes, size);
            return 0;
        }
    }
    return 1;
}
