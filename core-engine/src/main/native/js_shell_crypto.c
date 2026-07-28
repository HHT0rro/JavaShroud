#include "js_shell_crypto.h"

#include <stdint.h>
#include <string.h>

void js_shell_secure_wipe(void *bytes, size_t size) {
    volatile unsigned char *cursor = (volatile unsigned char *)bytes;
    while (cursor && size--) *cursor++ = 0;
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

static const unsigned char JS_SHELL_AES_SBOX[256] = {
    0x63u,0x7cu,0x77u,0x7bu,0xf2u,0x6bu,0x6fu,0xc5u,0x30u,0x01u,0x67u,0x2bu,0xfeu,0xd7u,0xabu,0x76u,
    0xcau,0x82u,0xc9u,0x7du,0xfau,0x59u,0x47u,0xf0u,0xadu,0xd4u,0xa2u,0xafu,0x9cu,0xa4u,0x72u,0xc0u,
    0xb7u,0xfdu,0x93u,0x26u,0x36u,0x3fu,0xf7u,0xccu,0x34u,0xa5u,0xe5u,0xf1u,0x71u,0xd8u,0x31u,0x15u,
    0x04u,0xc7u,0x23u,0xc3u,0x18u,0x96u,0x05u,0x9au,0x07u,0x12u,0x80u,0xe2u,0xebu,0x27u,0xb2u,0x75u,
    0x09u,0x83u,0x2cu,0x1au,0x1bu,0x6eu,0x5au,0xa0u,0x52u,0x3bu,0xd6u,0xb3u,0x29u,0xe3u,0x2fu,0x84u,
    0x53u,0xd1u,0x00u,0xedu,0x20u,0xfcu,0xb1u,0x5bu,0x6au,0xcbu,0xbeu,0x39u,0x4au,0x4cu,0x58u,0xcfu,
    0xd0u,0xefu,0xaau,0xfbu,0x43u,0x4du,0x33u,0x85u,0x45u,0xf9u,0x02u,0x7fu,0x50u,0x3cu,0x9fu,0xa8u,
    0x51u,0xa3u,0x40u,0x8fu,0x92u,0x9du,0x38u,0xf5u,0xbcu,0xb6u,0xdau,0x21u,0x10u,0xffu,0xf3u,0xd2u,
    0xcdu,0x0cu,0x13u,0xecu,0x5fu,0x97u,0x44u,0x17u,0xc4u,0xa7u,0x7eu,0x3du,0x64u,0x5du,0x19u,0x73u,
    0x60u,0x81u,0x4fu,0xdcu,0x22u,0x2au,0x90u,0x88u,0x46u,0xeeu,0xb8u,0x14u,0xdeu,0x5eu,0x0bu,0xdbu,
    0xe0u,0x32u,0x3au,0x0au,0x49u,0x06u,0x24u,0x5cu,0xc2u,0xd3u,0xacu,0x62u,0x91u,0x95u,0xe4u,0x79u,
    0xe7u,0xc8u,0x37u,0x6du,0x8du,0xd5u,0x4eu,0xa9u,0x6cu,0x56u,0xf4u,0xeau,0x65u,0x7au,0xaeu,0x08u,
    0xbau,0x78u,0x25u,0x2eu,0x1cu,0xa6u,0xb4u,0xc6u,0xe8u,0xddu,0x74u,0x1fu,0x4bu,0xbdu,0x8bu,0x8au,
    0x70u,0x3eu,0xb5u,0x66u,0x48u,0x03u,0xf6u,0x0eu,0x61u,0x35u,0x57u,0xb9u,0x86u,0xc1u,0x1du,0x9eu,
    0xe1u,0xf8u,0x98u,0x11u,0x69u,0xd9u,0x8eu,0x94u,0x9bu,0x1eu,0x87u,0xe9u,0xceu,0x55u,0x28u,0xdfu,
    0x8cu,0xa1u,0x89u,0x0du,0xbfu,0xe6u,0x42u,0x68u,0x41u,0x99u,0x2du,0x0fu,0xb0u,0x54u,0xbbu,0x16u
};
static const unsigned char JS_SHELL_AES_RCON[11] = {0x00u,0x01u,0x02u,0x04u,0x08u,0x10u,0x20u,0x40u,0x80u,0x1bu,0x36u};
static unsigned char js_shell_aes_xtime(unsigned char x) { return (unsigned char)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u)); }
static void js_shell_aes_expand(const unsigned char key[16], unsigned char expanded[176]) {
    int used = 16, rcon = 1;
    unsigned char temp[4];
    memcpy(expanded, key, 16u);
    while (used < 176) {
        memcpy(temp, expanded + used - 4, 4u);
        if ((used & 15) == 0) {
            unsigned char t = temp[0];
            temp[0] = (unsigned char)(JS_SHELL_AES_SBOX[temp[1]] ^ JS_SHELL_AES_RCON[rcon++]); temp[1] = JS_SHELL_AES_SBOX[temp[2]]; temp[2] = JS_SHELL_AES_SBOX[temp[3]]; temp[3] = JS_SHELL_AES_SBOX[t];
        }
        for (int i = 0; i < 4; i++, used++) expanded[used] = (unsigned char)(expanded[used - 16] ^ temp[i]);
    }
    js_shell_secure_wipe(temp, sizeof(temp));
}
static void js_shell_aes_block(const unsigned char in[16], const unsigned char key[16], unsigned char out[16]) {
    unsigned char state[16], expanded[176], t;
    memcpy(state, in, 16u); js_shell_aes_expand(key, expanded);
    for (int i = 0; i < 16; i++) state[i] ^= expanded[i];
    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++) state[i] = JS_SHELL_AES_SBOX[state[i]];
        t = state[1]; state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=t;
        t=state[2]; state[2]=state[10]; state[10]=t; t=state[6]; state[6]=state[14]; state[14]=t;
        t=state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=t;
        if (round != 10) for (int c=0;c<4;c++) {
            int i=c*4;
            unsigned char a=state[i],b=state[i+1],d=state[i+2],e=state[i+3],x=(unsigned char)(a^b^d^e);
            state[i]=(unsigned char)(a^js_shell_aes_xtime((unsigned char)(a^b))^x); state[i+1]=(unsigned char)(b^js_shell_aes_xtime((unsigned char)(b^d))^x); state[i+2]=(unsigned char)(d^js_shell_aes_xtime((unsigned char)(d^e))^x); state[i+3]=(unsigned char)(e^js_shell_aes_xtime((unsigned char)(e^a))^x);
        }
        for (int i=0;i<16;i++) state[i] ^= expanded[round*16+i];
    }
    memcpy(out,state,16u); js_shell_secure_wipe(state,sizeof(state)); js_shell_secure_wipe(expanded,sizeof(expanded));
}
static void js_shell_ctr_inc(unsigned char counter[16]) { for (int i=15;i>=0;i--) if (++counter[i] != 0u) break; }

void js_shell_aes128_ctr_xor(unsigned char *bytes, size_t size, const unsigned char key[16], const unsigned char iv[16]) {
    unsigned char counter[16], block[16];
    size_t offset = 0u, take;
    if (!bytes || !key || !iv) return;
    memcpy(counter, iv, 16u);
    while(offset<size) { js_shell_aes_block(counter,key,block); take=size-offset<16u?size-offset:16u; for(size_t i=0;i<take;i++) bytes[offset+i]^=block[i]; offset+=take; js_shell_ctr_inc(counter); }
    js_shell_secure_wipe(counter,sizeof(counter)); js_shell_secure_wipe(block,sizeof(block));
}

void js_shell_derive_stream_key(const unsigned char seed[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned char out[32]) {
    js_shell_kdf(seed, "javashroud-native-shell-stream-key-v3", nonce, binding_tag, 0u, out);
}

int js_shell_open_seed_envelope(const unsigned char boot_secret[32], const unsigned char seed_nonce[16], const unsigned char encrypted_seed[32], const unsigned char seed_tag[32], unsigned char seed_out[32]) {
    unsigned char zero_binding[32], tag_key[32], actual[32], seed_key[32], seed_iv_material[32];
    memset(zero_binding, 0, sizeof(zero_binding));
    js_shell_kdf(boot_secret, "javashroud-native-shell-seed-hmac-v3", seed_nonce, zero_binding, 0u, tag_key);
    js_shell_hmac_sha256(tag_key, sizeof(tag_key), encrypted_seed, 32u, actual);
    if (!js_shell_consttime_equal(actual, seed_tag, 32u)) {
        js_shell_secure_wipe(zero_binding,sizeof(zero_binding)); js_shell_secure_wipe(tag_key,sizeof(tag_key)); js_shell_secure_wipe(actual,sizeof(actual));
        return 0;
    }
    js_shell_kdf(boot_secret, "javashroud-native-shell-seed-key-v3", seed_nonce, zero_binding, 0u, seed_key);
    js_shell_kdf(boot_secret, "javashroud-native-shell-seed-iv-v3", seed_nonce, zero_binding, 0u, seed_iv_material);
    memcpy(seed_out, encrypted_seed, 32u);
    js_shell_aes128_ctr_xor(seed_out, 32u, seed_key, seed_iv_material);
    js_shell_secure_wipe(zero_binding,sizeof(zero_binding)); js_shell_secure_wipe(tag_key,sizeof(tag_key));
    js_shell_secure_wipe(actual,sizeof(actual)); js_shell_secure_wipe(seed_key,sizeof(seed_key)); js_shell_secure_wipe(seed_iv_material,sizeof(seed_iv_material));
    return 1;
}

int js_shell_open_sensitive_header(const unsigned char seed[32], const unsigned char nonce[16], const unsigned char *encrypted_header, size_t header_size, const unsigned char header_tag[32], unsigned char *plain_out) {
    unsigned char zero_binding[32], tag_key[32], actual[32], header_key[32], header_iv_material[32];
    memset(zero_binding, 0, sizeof(zero_binding));
    js_shell_kdf(seed, "javashroud-native-shell-header-hmac-v3", nonce, zero_binding, 0u, tag_key);
    js_shell_hmac_sha256(tag_key, sizeof(tag_key), encrypted_header, header_size, actual);
    if (!js_shell_consttime_equal(actual, header_tag, 32u)) {
        js_shell_secure_wipe(zero_binding,sizeof(zero_binding)); js_shell_secure_wipe(tag_key,sizeof(tag_key)); js_shell_secure_wipe(actual,sizeof(actual));
        return 0;
    }
    js_shell_kdf(seed, "javashroud-native-shell-header-key-v3", nonce, zero_binding, 0u, header_key);
    js_shell_kdf(seed, "javashroud-native-shell-header-iv-v3", nonce, zero_binding, 0u, header_iv_material);
    memcpy(plain_out, encrypted_header, header_size);
    js_shell_aes128_ctr_xor(plain_out, header_size, header_key, header_iv_material);
    js_shell_secure_wipe(zero_binding,sizeof(zero_binding)); js_shell_secure_wipe(tag_key,sizeof(tag_key));
    js_shell_secure_wipe(actual,sizeof(actual)); js_shell_secure_wipe(header_key,sizeof(header_key)); js_shell_secure_wipe(header_iv_material,sizeof(header_iv_material));
    return 1;
}

static int js_shell_decode_chunk(unsigned char *bytes, size_t length, const unsigned char stream_key[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int chunk_index, const unsigned char expected_tag[32]) {
    unsigned char chunk_key[32], tag_key[32], actual[32], iv_material[32];
    int ok = 0;
    js_shell_kdf(stream_key, "javashroud-native-shell-chunk-aes-v3", nonce, binding_tag, chunk_index, chunk_key);
    js_shell_kdf(stream_key, "javashroud-native-shell-chunk-hmac-v3", nonce, binding_tag, chunk_index, tag_key);
    js_shell_kdf(stream_key, "javashroud-native-shell-chunk-iv-v3", nonce, binding_tag, chunk_index, iv_material);
    js_shell_hmac_sha256(tag_key, sizeof(tag_key), bytes, length, actual);
    ok = js_shell_consttime_equal(actual, expected_tag, 32u);
    if (ok) js_shell_aes128_ctr_xor(bytes, length, chunk_key, iv_material);
    js_shell_secure_wipe(chunk_key,sizeof(chunk_key)); js_shell_secure_wipe(tag_key,sizeof(tag_key)); js_shell_secure_wipe(actual,sizeof(actual)); js_shell_secure_wipe(iv_material,sizeof(iv_material));
    return ok;
}

int js_shell_decode_payload_chunks(unsigned char *bytes, size_t size, const unsigned char stream_key[32], const unsigned char nonce[16], const unsigned char binding_tag[32], unsigned int chunk_size, const unsigned char *chunk_tags, size_t chunk_tags_size) {
    size_t chunk_count, offset, length;
    if (!bytes || !stream_key || !nonce || !binding_tag || !chunk_tags || chunk_size == 0u) return 0;
    chunk_count = size == 0u ? 0u : 1u + (size - 1u) / (size_t)chunk_size;
    if (chunk_count > SIZE_MAX / 32u || chunk_tags_size != chunk_count * 32u) return 0;
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
