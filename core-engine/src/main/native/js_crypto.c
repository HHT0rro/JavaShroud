#include "js_crypto.h"
#include <string.h>

JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

static uint32_t js_vbc4_rotr32(uint32_t value, int bits) { int sh = bits & 31; return sh == 0 ? value : (value >> sh) | (value << (32 - sh)); }

static const uint32_t JS_SHA256_K[64] = {
    0x428A2F98u,0x71374491u,0xB5C0FBCFu,0xE9B5DBA5u,0x3956C25Bu,0x59F111F1u,0x923F82A4u,0xAB1C5ED5u,
    0xD807AA98u,0x12835B01u,0x243185BEu,0x550C7DC3u,0x72BE5D74u,0x80DEB1FEu,0x9BDC06A7u,0xC19BF174u,
    0xE49B69C1u,0xEFBE4786u,0x0FC19DC6u,0x240CA1CCu,0x2DE92C6Fu,0x4A7484AAu,0x5CB0A9DCu,0x76F988DAu,
    0x983E5152u,0xA831C66Du,0xB00327C8u,0xBF597FC7u,0xC6E00BF3u,0xD5A79147u,0x06CA6351u,0x14292967u,
    0x27B70A85u,0x2E1B2138u,0x4D2C6DFCu,0x53380D13u,0x650A7354u,0x766A0ABBu,0x81C2C92Eu,0x92722C85u,
    0xA2BFE8A1u,0xA81A664Bu,0xC24B8B70u,0xC76C51A3u,0xD192E819u,0xD6990624u,0xF40E3585u,0x106AA070u,
    0x19A4C116u,0x1E376C08u,0x2748774Cu,0x34B0BCB5u,0x391C0CB3u,0x4ED8AA4Au,0x5B9CCA4Fu,0x682E6FF3u,
    0x748F82EEu,0x78A5636Fu,0x84C87814u,0x8CC70208u,0x90BEFFFAu,0xA4506CEBu,0xBEF9A3F7u,0xC67178F2u
};

static void js_sha256_transform(js_sha256_ctx *ctx, const unsigned char data[64]) {
    uint32_t words[64];
    for (uint32_t index = 0; index < 16; index++) {
        words[index] = ((uint32_t)data[index * 4] << 24) | ((uint32_t)data[index * 4 + 1] << 16) |
                       ((uint32_t)data[index * 4 + 2] << 8) | (uint32_t)data[index * 4 + 3];
    }
    for (uint32_t index = 16; index < 64; index++) {
        uint32_t s0 = js_vbc4_rotr32(words[index - 15], 7) ^ js_vbc4_rotr32(words[index - 15], 18) ^ (words[index - 15] >> 3);
        uint32_t s1 = js_vbc4_rotr32(words[index - 2], 17) ^ js_vbc4_rotr32(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    uint32_t a_state = ctx->state[0];
    uint32_t b_state = ctx->state[1];
    uint32_t c_state = ctx->state[2];
    uint32_t d_state = ctx->state[3];
    uint32_t e_state = ctx->state[4];
    uint32_t f_state = ctx->state[5];
    uint32_t g_state = ctx->state[6];
    uint32_t h_state = ctx->state[7];
    for (uint32_t index = 0; index < 64; index++) {
        uint32_t s1 = js_vbc4_rotr32(e_state, 6) ^ js_vbc4_rotr32(e_state, 11) ^ js_vbc4_rotr32(e_state, 25);
        uint32_t choice = (e_state & f_state) ^ ((~e_state) & g_state);
        uint32_t temp1 = h_state + s1 + choice + JS_SHA256_K[index] + words[index];
        uint32_t s0 = js_vbc4_rotr32(a_state, 2) ^ js_vbc4_rotr32(a_state, 13) ^ js_vbc4_rotr32(a_state, 22);
        uint32_t majority = (a_state & b_state) ^ (a_state & c_state) ^ (b_state & c_state);
        uint32_t temp2 = s0 + majority;
        h_state = g_state;
        g_state = f_state;
        f_state = e_state;
        e_state = d_state + temp1;
        d_state = c_state;
        c_state = b_state;
        b_state = a_state;
        a_state = temp1 + temp2;
    }
    ctx->state[0] += a_state; ctx->state[1] += b_state; ctx->state[2] += c_state; ctx->state[3] += d_state;
    ctx->state[4] += e_state; ctx->state[5] += f_state; ctx->state[6] += g_state; ctx->state[7] += h_state;
}

JS_HIDDEN void js_sha256_init(js_sha256_ctx *ctx) {
    ctx->data_len = 0;
    ctx->bit_len = 0;
    ctx->state[0] = 0x6A09E667u; ctx->state[1] = 0xBB67AE85u; ctx->state[2] = 0x3C6EF372u; ctx->state[3] = 0xA54FF53Au;
    ctx->state[4] = 0x510E527Fu; ctx->state[5] = 0x9B05688Cu; ctx->state[6] = 0x1F83D9ABu; ctx->state[7] = 0x5BE0CD19u;
}

JS_HIDDEN void js_sha256_update(js_sha256_ctx *ctx, const unsigned char *data, int len) {
    if (!data || len <= 0) return;
    for (int index = 0; index < len; index++) {
        ctx->data[ctx->data_len++] = data[index];
        if (ctx->data_len == 64) {
            js_sha256_transform(ctx, ctx->data);
            ctx->bit_len += 512u;
            ctx->data_len = 0;
        }
    }
}

JS_HIDDEN void js_sha256_final(js_sha256_ctx *ctx, unsigned char hash[32]) {
    uint32_t index = ctx->data_len;
    ctx->data[index++] = 0x80u;
    if (index > 56) {
        while (index < 64) ctx->data[index++] = 0;
        js_sha256_transform(ctx, ctx->data);
        index = 0;
    }
    while (index < 56) ctx->data[index++] = 0;
    ctx->bit_len += (uint64_t)ctx->data_len * 8u;
    for (int shift = 0; shift < 8; shift++) ctx->data[63 - shift] = (unsigned char)(ctx->bit_len >> (shift * 8));
    js_sha256_transform(ctx, ctx->data);
    for (int state_index = 0; state_index < 8; state_index++) {
        hash[state_index * 4] = (unsigned char)(ctx->state[state_index] >> 24);
        hash[state_index * 4 + 1] = (unsigned char)(ctx->state[state_index] >> 16);
        hash[state_index * 4 + 2] = (unsigned char)(ctx->state[state_index] >> 8);
        hash[state_index * 4 + 3] = (unsigned char)ctx->state[state_index];
    }
}

static const unsigned char JS_AES_SBOX[256] = {
    0x63u,0x7Cu,0x77u,0x7Bu,0xF2u,0x6Bu,0x6Fu,0xC5u,0x30u,0x01u,0x67u,0x2Bu,0xFEu,0xD7u,0xABu,0x76u,
    0xCAu,0x82u,0xC9u,0x7Du,0xFAu,0x59u,0x47u,0xF0u,0xADu,0xD4u,0xA2u,0xAFu,0x9Cu,0xA4u,0x72u,0xC0u,
    0xB7u,0xFDu,0x93u,0x26u,0x36u,0x3Fu,0xF7u,0xCCu,0x34u,0xA5u,0xE5u,0xF1u,0x71u,0xD8u,0x31u,0x15u,
    0x04u,0xC7u,0x23u,0xC3u,0x18u,0x96u,0x05u,0x9Au,0x07u,0x12u,0x80u,0xE2u,0xEBu,0x27u,0xB2u,0x75u,
    0x09u,0x83u,0x2Cu,0x1Au,0x1Bu,0x6Eu,0x5Au,0xA0u,0x52u,0x3Bu,0xD6u,0xB3u,0x29u,0xE3u,0x2Fu,0x84u,
    0x53u,0xD1u,0x00u,0xEDu,0x20u,0xFCu,0xB1u,0x5Bu,0x6Au,0xCBu,0xBEu,0x39u,0x4Au,0x4Cu,0x58u,0xCFu,
    0xD0u,0xEFu,0xAAu,0xFBu,0x43u,0x4Du,0x33u,0x85u,0x45u,0xF9u,0x02u,0x7Fu,0x50u,0x3Cu,0x9Fu,0xA8u,
    0x51u,0xA3u,0x40u,0x8Fu,0x92u,0x9Du,0x38u,0xF5u,0xBCu,0xB6u,0xDAu,0x21u,0x10u,0xFFu,0xF3u,0xD2u,
    0xCDu,0x0Cu,0x13u,0xECu,0x5Fu,0x97u,0x44u,0x17u,0xC4u,0xA7u,0x7Eu,0x3Du,0x64u,0x5Du,0x19u,0x73u,
    0x60u,0x81u,0x4Fu,0xDCu,0x22u,0x2Au,0x90u,0x88u,0x46u,0xEEu,0xB8u,0x14u,0xDEu,0x5Eu,0x0Bu,0xDBu,
    0xE0u,0x32u,0x3Au,0x0Au,0x49u,0x06u,0x24u,0x5Cu,0xC2u,0xD3u,0xACu,0x62u,0x91u,0x95u,0xE4u,0x79u,
    0xE7u,0xC8u,0x37u,0x6Du,0x8Du,0xD5u,0x4Eu,0xA9u,0x6Cu,0x56u,0xF4u,0xEAu,0x65u,0x7Au,0xAEu,0x08u,
    0xBAu,0x78u,0x25u,0x2Eu,0x1Cu,0xA6u,0xB4u,0xC6u,0xE8u,0xDDu,0x74u,0x1Fu,0x4Bu,0xBDu,0x8Bu,0x8Au,
    0x70u,0x3Eu,0xB5u,0x66u,0x48u,0x03u,0xF6u,0x0Eu,0x61u,0x35u,0x57u,0xB9u,0x86u,0xC1u,0x1Du,0x9Eu,
    0xE1u,0xF8u,0x98u,0x11u,0x69u,0xD9u,0x8Eu,0x94u,0x9Bu,0x1Eu,0x87u,0xE9u,0xCEu,0x55u,0x28u,0xDFu,
    0x8Cu,0xA1u,0x89u,0x0Du,0xBFu,0xE6u,0x42u,0x68u,0x41u,0x99u,0x2Du,0x0Fu,0xB0u,0x54u,0xBBu,0x16u
};
static const unsigned char JS_AES_RCON[11] = {0x00u,0x01u,0x02u,0x04u,0x08u,0x10u,0x20u,0x40u,0x80u,0x1Bu,0x36u};

static unsigned char js_aes_xtime(unsigned char x) { return (unsigned char)((x << 1) ^ ((x & 0x80u) ? 0x1Bu : 0x00u)); }
static void js_aes_add_round_key(unsigned char state[16], const unsigned char *round_key) { for (int i = 0; i < 16; i++) state[i] ^= round_key[i]; }
static void js_aes_sub_bytes(unsigned char state[16]) { for (int i = 0; i < 16; i++) state[i] = JS_AES_SBOX[state[i]]; }
static void js_aes_shift_rows(unsigned char state[16]) {
    unsigned char t;
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}
static void js_aes_mix_columns(unsigned char state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a = state[i], b = state[i + 1], d = state[i + 2], e = state[i + 3];
        unsigned char x = (unsigned char)(a ^ b ^ d ^ e);
        unsigned char xa = js_aes_xtime((unsigned char)(a ^ b));
        unsigned char xb = js_aes_xtime((unsigned char)(b ^ d));
        unsigned char xd = js_aes_xtime((unsigned char)(d ^ e));
        unsigned char xe = js_aes_xtime((unsigned char)(e ^ a));
        state[i] = (unsigned char)(a ^ xa ^ x);
        state[i + 1] = (unsigned char)(b ^ xb ^ x);
        state[i + 2] = (unsigned char)(d ^ xd ^ x);
        state[i + 3] = (unsigned char)(e ^ xe ^ x);
    }
}
static void js_aes_expand_key(const unsigned char key[16], unsigned char expanded[176]) {
    memcpy(expanded, key, 16);
    int bytes = 16;
    int rcon = 1;
    unsigned char temp[4];
    while (bytes < 176) {
        for (int i = 0; i < 4; i++) temp[i] = expanded[bytes - 4 + i];
        if (bytes % 16 == 0) {
            unsigned char t = temp[0];
            temp[0] = (unsigned char)(JS_AES_SBOX[temp[1]] ^ JS_AES_RCON[rcon++]);
            temp[1] = JS_AES_SBOX[temp[2]];
            temp[2] = JS_AES_SBOX[temp[3]];
            temp[3] = JS_AES_SBOX[t];
        }
        for (int i = 0; i < 4; i++) { expanded[bytes] = (unsigned char)(expanded[bytes - 16] ^ temp[i]); bytes++; }
    }
}
JS_HIDDEN void js_aes128_encrypt_block(const unsigned char in[16], const unsigned char key[16], unsigned char out[16]) {
    unsigned char state[16];
    unsigned char expanded[176];
    memcpy(state, in, 16);
    js_aes_expand_key(key, expanded);
    js_aes_add_round_key(state, expanded);
    for (int round = 1; round < 10; round++) {
        js_aes_sub_bytes(state);
        js_aes_shift_rows(state);
        js_aes_mix_columns(state);
        js_aes_add_round_key(state, expanded + round * 16);
    }
    js_aes_sub_bytes(state);
    js_aes_shift_rows(state);
    js_aes_add_round_key(state, expanded + 160);
    memcpy(out, state, 16);
    js_vbc4_wipe_volatile(state, sizeof(state));
    js_vbc4_wipe_volatile(expanded, sizeof(expanded));
}

JS_HIDDEN void js_ctr_inc(unsigned char counter[16]) { for (int i = 15; i >= 0; i--) { counter[i] = (unsigned char)(counter[i] + 1u); if (counter[i] != 0) break; } }
