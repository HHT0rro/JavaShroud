#include "js_crypto.h"
#include <string.h>

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
#if defined(_MSC_VER)
#include <intrin.h>
#include <wmmintrin.h>
#define JS_AES_HW_DISPATCH 1
#define JS_AES_HW_TARGET
#define JS_PCLMUL_HW_TARGET __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#include <wmmintrin.h>
#define JS_AES_HW_DISPATCH 1
#define JS_AES_HW_TARGET __attribute__((target("aes"), noinline))
#define JS_PCLMUL_HW_TARGET __attribute__((target("pclmul"), noinline))
#endif
#endif

#ifndef JS_AES_HW_DISPATCH
#define JS_AES_HW_DISPATCH 0
#define JS_AES_HW_TARGET
#define JS_PCLMUL_HW_TARGET
#endif

/* Test-only capability-disabled builds exercise the same authoritative
 * software implementation without compiling or selecting an intrinsic
 * dispatch path.  Production builds do not define this macro; runtime CPU
 * detection and the self-tests above remain the only hardware gate. */
#if defined(JS_CRYPTO_DISABLE_HARDWARE)
#undef JS_AES_HW_DISPATCH
#define JS_AES_HW_DISPATCH 0
#endif

/*
 * Runtime counters are touched from crypto, VM, resource, JNI, and loader
 * threads, while AES capability selection is a once-only cross-thread state
 * transition.  The public js_crypto_runtime_metrics type intentionally remains
 * a plain uint64_t snapshot ABI; keeping atomics in this private backing store
 * avoids exposing a compiler-specific atomic layout to callers.
 *
 * Clang/GCC builds use C11 atomics.  Native MSVC builds retain a Windows
 * Interlocked fallback for toolchains that do not provide a usable C11
 * <stdatomic.h>; the compiler-builtin branch lets older GCC/Clang targets use
 * the same code without weakening the synchronization contract.  All paths
 * use relaxed counter operations because metrics do not publish application
 * data.  They still eliminate data races and torn 64-bit reads/writes.
 */
#if (defined(__clang__) || defined(__GNUC__)) && \
    (!defined(__STDC_NO_ATOMICS__) || (__STDC_NO_ATOMICS__ == 0)) && \
    !defined(JS_RUNTIME_METRICS_FORCE_COMPILER_ATOMICS)
#include <stdatomic.h>
typedef _Atomic(uint64_t) js_runtime_metrics_atomic_counter;
typedef _Atomic(int) js_runtime_atomic_int;

static uint64_t js_runtime_metrics_atomic_load(const js_runtime_metrics_atomic_counter *value) {
    return atomic_load_explicit(value, memory_order_relaxed);
}

static void js_runtime_metrics_atomic_store(js_runtime_metrics_atomic_counter *value, uint64_t next) {
    atomic_store_explicit(value, next, memory_order_relaxed);
}

static void js_runtime_metrics_atomic_increment(js_runtime_metrics_atomic_counter *value) {
    (void)atomic_fetch_add_explicit(value, UINT64_C(1), memory_order_relaxed);
}

static void js_runtime_metrics_atomic_add(js_runtime_metrics_atomic_counter *value, uint64_t amount) {
    (void)atomic_fetch_add_explicit(value, amount, memory_order_relaxed);
}

static int js_runtime_atomic_int_load_acquire(const js_runtime_atomic_int *value) {
    return atomic_load_explicit(value, memory_order_acquire);
}

static int js_runtime_atomic_int_compare_exchange_acq_rel(
    js_runtime_atomic_int *value,
    int *expected,
    int desired
) {
    return atomic_compare_exchange_strong_explicit(
        value,
        expected,
        desired,
        memory_order_acq_rel,
        memory_order_acquire);
}

static void js_runtime_atomic_int_store_release(js_runtime_atomic_int *value, int next) {
    atomic_store_explicit(value, next, memory_order_release);
}
#elif defined(_MSC_VER) && !defined(__clang__)
#include <windows.h>
typedef volatile LONG64 js_runtime_metrics_atomic_counter;
typedef volatile LONG js_runtime_atomic_int;

static uint64_t js_runtime_metrics_atomic_load(const js_runtime_metrics_atomic_counter *value) {
    return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)(void *)value, 0, 0);
}

static void js_runtime_metrics_atomic_store(js_runtime_metrics_atomic_counter *value, uint64_t next) {
    (void)InterlockedExchange64(value, (LONG64)next);
}

static void js_runtime_metrics_atomic_increment(js_runtime_metrics_atomic_counter *value) {
    (void)InterlockedIncrement64(value);
}

static void js_runtime_metrics_atomic_add(js_runtime_metrics_atomic_counter *value, uint64_t amount) {
    (void)InterlockedAdd64(value, (LONG64)amount);
}

static int js_runtime_atomic_int_load_acquire(const js_runtime_atomic_int *value) {
    return (int)InterlockedCompareExchange((volatile LONG *)(void *)value, 0, 0);
}

static int js_runtime_atomic_int_compare_exchange_acq_rel(
    js_runtime_atomic_int *value,
    int *expected,
    int desired
) {
    LONG observed;
    if (!value || !expected) return 0;
    observed = InterlockedCompareExchange(value, (LONG)desired, (LONG)*expected);
    if (observed == (LONG)*expected) return 1;
    *expected = (int)observed;
    return 0;
}

static void js_runtime_atomic_int_store_release(js_runtime_atomic_int *value, int next) {
    (void)InterlockedExchange(value, (LONG)next);
}
#elif defined(__clang__) || defined(__GNUC__)
typedef uint64_t js_runtime_metrics_atomic_counter;
typedef int js_runtime_atomic_int;

static uint64_t js_runtime_metrics_atomic_load(const js_runtime_metrics_atomic_counter *value) {
    return __atomic_load_n(value, __ATOMIC_RELAXED);
}

static void js_runtime_metrics_atomic_store(js_runtime_metrics_atomic_counter *value, uint64_t next) {
    __atomic_store_n(value, next, __ATOMIC_RELAXED);
}

static void js_runtime_metrics_atomic_increment(js_runtime_metrics_atomic_counter *value) {
    (void)__atomic_fetch_add(value, UINT64_C(1), __ATOMIC_RELAXED);
}

static void js_runtime_metrics_atomic_add(js_runtime_metrics_atomic_counter *value, uint64_t amount) {
    (void)__atomic_fetch_add(value, amount, __ATOMIC_RELAXED);
}

static int js_runtime_atomic_int_load_acquire(const js_runtime_atomic_int *value) {
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static int js_runtime_atomic_int_compare_exchange_acq_rel(
    js_runtime_atomic_int *value,
    int *expected,
    int desired
) {
    return __atomic_compare_exchange_n(
        value,
        expected,
        desired,
        0,
        __ATOMIC_ACQ_REL,
        __ATOMIC_ACQUIRE);
}

static void js_runtime_atomic_int_store_release(js_runtime_atomic_int *value, int next) {
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
}
#else
#error "JavaShroud runtime metrics require C11 atomics or a supported compiler atomic fallback"
#endif

#define JS_CRYPTO_RUNTIME_METRIC_FIELDS(X) \
    X(hardware_crypto_path) \
    X(software_crypto_path) \
    X(aes_block_count) \
    X(ghash_block_count) \
    X(vm_frame_reuse_count) \
    X(vm_heap_fallback_count) \
    X(resource_index_hit_count) \
    X(decompress_context_reuse_count) \
    X(jni_cache_hit_count) \
    X(auth_check_count) \
    X(auth_failure_count) \
    X(digest_check_count) \
    X(tag_check_count) \
    X(length_check_count) \
    X(structure_check_count) \
    X(jni_abi_check_count) \
    X(wipe_count) \
    X(wipe_failure_count) \
    X(plaintext_persistence_bytes) \
    X(fallback_count) \
    X(legacy_path_hits) \
    X(exception_count) \
    X(security_checks_skipped) \
    X(phase_p50) \
    X(phase_p95) \
    X(phase_max)

typedef struct {
#define JS_CRYPTO_RUNTIME_METRIC_ATOMIC_FIELD(name) js_runtime_metrics_atomic_counter name;
    JS_CRYPTO_RUNTIME_METRIC_FIELDS(JS_CRYPTO_RUNTIME_METRIC_ATOMIC_FIELD)
#undef JS_CRYPTO_RUNTIME_METRIC_ATOMIC_FIELD
} js_crypto_runtime_metrics_atomic;

static js_crypto_runtime_metrics_atomic js_crypto_metrics;

JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);

/* Reset and snapshot are data-race-free per-counter operations.  Benchmark
 * phase boundaries quiesce their workers before using reset/snapshot when they
 * require a single cross-counter boundary; a concurrently sampled snapshot is
 * intentionally a pointwise, atomically-read observation rather than a
 * transaction that serializes production hot paths. */
JS_HIDDEN void js_crypto_runtime_metrics_reset(void) {
#define JS_CRYPTO_RUNTIME_METRIC_RESET_FIELD(name) \
    js_runtime_metrics_atomic_store(&js_crypto_metrics.name, UINT64_C(0));
    JS_CRYPTO_RUNTIME_METRIC_FIELDS(JS_CRYPTO_RUNTIME_METRIC_RESET_FIELD)
#undef JS_CRYPTO_RUNTIME_METRIC_RESET_FIELD
}

JS_HIDDEN void js_crypto_runtime_metrics_snapshot(js_crypto_runtime_metrics *out) {
    if (!out) return;
#define JS_CRYPTO_RUNTIME_METRIC_SNAPSHOT_FIELD(name) \
    out->name = js_runtime_metrics_atomic_load(&js_crypto_metrics.name);
    JS_CRYPTO_RUNTIME_METRIC_FIELDS(JS_CRYPTO_RUNTIME_METRIC_SNAPSHOT_FIELD)
#undef JS_CRYPTO_RUNTIME_METRIC_SNAPSHOT_FIELD
}

#undef JS_CRYPTO_RUNTIME_METRIC_FIELDS

static void js_crypto_metric_increment(js_runtime_metrics_atomic_counter *value) {
    if (value) js_runtime_metrics_atomic_increment(value);
}

static void js_crypto_metric_add(js_runtime_metrics_atomic_counter *value, uint64_t amount) {
    if (value && amount != 0u) js_runtime_metrics_atomic_add(value, amount);
}

JS_HIDDEN void js_runtime_metrics_note_vm_frame_reuse(void) { js_crypto_metric_increment(&js_crypto_metrics.vm_frame_reuse_count); }
JS_HIDDEN void js_runtime_metrics_note_vm_heap_fallback(void) { js_crypto_metric_increment(&js_crypto_metrics.vm_heap_fallback_count); }
JS_HIDDEN void js_runtime_metrics_note_resource_index_hit(void) { js_crypto_metric_increment(&js_crypto_metrics.resource_index_hit_count); }
JS_HIDDEN void js_runtime_metrics_note_decompress_context_reuse(void) { js_crypto_metric_increment(&js_crypto_metrics.decompress_context_reuse_count); }
JS_HIDDEN void js_runtime_metrics_note_jni_cache_hit(void) { js_crypto_metric_increment(&js_crypto_metrics.jni_cache_hit_count); }
JS_HIDDEN void js_runtime_metrics_note_auth_check(void) { js_crypto_metric_increment(&js_crypto_metrics.auth_check_count); }
JS_HIDDEN void js_runtime_metrics_note_auth_failure(void) { js_crypto_metric_increment(&js_crypto_metrics.auth_failure_count); }
JS_HIDDEN void js_runtime_metrics_note_digest_check(void) { js_crypto_metric_increment(&js_crypto_metrics.digest_check_count); }
JS_HIDDEN void js_runtime_metrics_note_tag_check(void) { js_crypto_metric_increment(&js_crypto_metrics.tag_check_count); }
JS_HIDDEN void js_runtime_metrics_note_length_check(void) { js_crypto_metric_increment(&js_crypto_metrics.length_check_count); }
JS_HIDDEN void js_runtime_metrics_note_structure_check(void) { js_crypto_metric_increment(&js_crypto_metrics.structure_check_count); }
JS_HIDDEN void js_runtime_metrics_note_jni_abi_check(void) { js_crypto_metric_increment(&js_crypto_metrics.jni_abi_check_count); }
JS_HIDDEN void js_runtime_metrics_note_fallback(void) { js_crypto_metric_increment(&js_crypto_metrics.fallback_count); }
JS_HIDDEN void js_runtime_metrics_note_exception(void) { js_crypto_metric_increment(&js_crypto_metrics.exception_count); }

JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
    js_crypto_metric_increment(&js_crypto_metrics.wipe_count);
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


/* Complete an AES-256 expansion after the caller has populated its first
 * eight key words.  Keeping this tail separate lets the typed AKEN terminal
 * initialize an operation-local schedule directly from scalar lanes, without
 * retaining a second key buffer or falling back to per-block expansion. */
static void js_aes256_expand_key_tail(unsigned char expanded[240]) {
    int bytes = 32;
    unsigned char rcon = 0x01u;
    unsigned char temp[4];
    while (bytes < 240) {
        memcpy(temp, expanded + bytes - 4, sizeof(temp));
        if ((bytes & 31) == 0) {
            unsigned char first = temp[0];
            temp[0] = (unsigned char)(JS_AES_SBOX[temp[1]] ^ rcon);
            temp[1] = JS_AES_SBOX[temp[2]];
            temp[2] = JS_AES_SBOX[temp[3]];
            temp[3] = JS_AES_SBOX[first];
            rcon = js_aes_xtime(rcon);
        } else if ((bytes & 31) == 16) {
            for (int i = 0; i < 4; i++) temp[i] = JS_AES_SBOX[temp[i]];
        }
        for (int i = 0; i < 4; i++, bytes++) expanded[bytes] = (unsigned char)(expanded[bytes - 32] ^ temp[i]);
    }
    js_vbc4_wipe_volatile(temp, sizeof(temp));
}

static void js_aes256_expand_key(const unsigned char key[32], unsigned char expanded[240]) {
    if (!key || !expanded) return;
    memcpy(expanded, key, 32u);
    js_aes256_expand_key_tail(expanded);
}

/*
 * A GCM operation encrypts H, J0 and every counter block with the same key.
 * The previous implementation expanded that key for every block, which made
 * long authenticated pages needlessly dominated by key-schedule work.  Keep
 * the exact AES round function and key material, but retain one wiped schedule
 * for the duration of a single authenticated operation.  The schedule never
 * escapes the call, is not cached across sessions/artifacts, and is wiped on
 * every exit path.
 */
typedef struct {
    unsigned char round_keys[240];
    unsigned int rounds;
    unsigned int key_len;
    unsigned int initialized;
} js_aes_schedule;

static void js_aes_dispatch_init(void);
static int js_aes_dispatch_uses_hardware(void);

static int js_aes_schedule_init(js_aes_schedule *schedule, const unsigned char *key, size_t key_len) {
    if (!schedule || !key || (key_len != 16u && key_len != 32u)) return 0;
    memset(schedule, 0, sizeof(*schedule));
    if (key_len == 16u) {
        js_aes_expand_key(key, schedule->round_keys);
        schedule->rounds = 10u;
    } else {
        js_aes256_expand_key(key, schedule->round_keys);
        schedule->rounds = 14u;
    }
    schedule->key_len = (unsigned int)key_len;
    schedule->initialized = 1u;
    js_aes_dispatch_init();
    js_crypto_metric_increment(js_aes_dispatch_uses_hardware()
        ? &js_crypto_metrics.hardware_crypto_path
        : &js_crypto_metrics.software_crypto_path);
    return 1;
}

static void js_aes_schedule_store_be32(unsigned char out[4], uint32_t lane) {
    if (!out) return;
    out[0] = (unsigned char)(lane >> 24u);
    out[1] = (unsigned char)(lane >> 16u);
    out[2] = (unsigned char)(lane >> 8u);
    out[3] = (unsigned char)lane;
}

/* The page-bound terminal receives AES-256 material as independent scalar
 * lanes.  Expand those lanes once into the same short-lived schedule used by
 * the ordinary GCM path: H, J0/tag mask, and all counter blocks therefore
 * share one validated key schedule.  The schedule is local to one operation
 * and is wiped by the caller on every outcome. */
static int js_aes_schedule_init_lanes(
    js_aes_schedule *schedule,
    uint32_t lane0,
    uint32_t lane1,
    uint32_t lane2,
    uint32_t lane3,
    uint32_t lane4,
    uint32_t lane5,
    uint32_t lane6,
    uint32_t lane7
) {
    if (!schedule) return 0;
    memset(schedule, 0, sizeof(*schedule));
    js_aes_schedule_store_be32(schedule->round_keys, lane0);
    js_aes_schedule_store_be32(schedule->round_keys + 4u, lane1);
    js_aes_schedule_store_be32(schedule->round_keys + 8u, lane2);
    js_aes_schedule_store_be32(schedule->round_keys + 12u, lane3);
    js_aes_schedule_store_be32(schedule->round_keys + 16u, lane4);
    js_aes_schedule_store_be32(schedule->round_keys + 20u, lane5);
    js_aes_schedule_store_be32(schedule->round_keys + 24u, lane6);
    js_aes_schedule_store_be32(schedule->round_keys + 28u, lane7);
    js_aes256_expand_key_tail(schedule->round_keys);
    schedule->rounds = 14u;
    schedule->key_len = 32u;
    schedule->initialized = 1u;
    js_aes_dispatch_init();
    js_crypto_metric_increment(js_aes_dispatch_uses_hardware()
        ? &js_crypto_metrics.hardware_crypto_path
        : &js_crypto_metrics.software_crypto_path);
    return 1;
}

static void js_aes_schedule_encrypt_block_sw(
    const js_aes_schedule *schedule,
    const unsigned char in[16],
    unsigned char out[16]
) {
    unsigned char state[16];
    if (!schedule || !schedule->initialized || !in || !out) return;
    memcpy(state, in, sizeof(state));
    js_aes_add_round_key(state, schedule->round_keys);
    for (unsigned int round = 1u; round < schedule->rounds; round++) {
        js_aes_sub_bytes(state);
        js_aes_shift_rows(state);
        js_aes_mix_columns(state);
        js_aes_add_round_key(state, schedule->round_keys + round * 16u);
    }
    js_aes_sub_bytes(state);
    js_aes_shift_rows(state);
    js_aes_add_round_key(state, schedule->round_keys + schedule->rounds * 16u);
    memcpy(out, state, sizeof(state));
    js_vbc4_wipe_volatile(state, sizeof(state));
}

#if JS_AES_HW_DISPATCH && !defined(JS_CRYPTO_FORCE_SOFTWARE)
static int js_aes_runtime_has_aes(void) {
#if defined(_MSC_VER)
    int registers[4];
    __cpuidex(registers, 1, 0);
    return (registers[2] & (1 << 25)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax = 0u, ebx = 0u, ecx = 0u, edx = 0u;
    if (!__get_cpuid(1u, &eax, &ebx, &ecx, &edx)) return 0;
    return (ecx & (1u << 25)) != 0u;
#else
    return 0;
#endif
}

static int js_aes_runtime_has_pclmul(void) {
#if defined(_MSC_VER)
    int registers[4];
    __cpuidex(registers, 1, 0);
    return (registers[2] & (1 << 1)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax = 0u, ebx = 0u, ecx = 0u, edx = 0u;
    if (!__get_cpuid(1u, &eax, &ebx, &ecx, &edx)) return 0;
    return (ecx & (1u << 1)) != 0u;
#else
    return 0;
#endif
}

/*
 * GHASH uses the reflected form of GF(2^128), while PCLMUL operates on the
 * conventional least-significant-bit polynomial representation.  Reading the
 * byte arrays as native little-endian words means that only bits *within* each
 * byte need reflection: the previous byte-order reversal and big-endian loads
 * cancelled each other.  Keep this scalar and table-free because these inputs
 * include authenticated state and the hash subkey.
 */
static uint64_t js_gcm_reverse_bits_in_each_byte64(uint64_t value) {
    value = ((value >> 1u) & UINT64_C(0x5555555555555555)) |
        ((value & UINT64_C(0x5555555555555555)) << 1u);
    value = ((value >> 2u) & UINT64_C(0x3333333333333333)) |
        ((value & UINT64_C(0x3333333333333333)) << 2u);
    value = ((value >> 4u) & UINT64_C(0x0f0f0f0f0f0f0f0f)) |
        ((value & UINT64_C(0x0f0f0f0f0f0f0f0f)) << 4u);
    return value;
}

/*
 * Reduce a 256-bit polynomial in product[0..3] modulo
 * x^128 + x^7 + x^2 + x + 1.  Writing r = 0x87 gives
 *
 *     L + H*x^128 == L + H*r (mod p).
 *
 * H*r can exceed bit 127 by only seven bits.  Fold those seven bits once more
 * with r, so this replaces the old fixed 128-iteration bit reduction with
 * fixed shifts/XORs.  The sequence is independent of both operands.
 */
static void js_gcm_reduce_product_fast(uint64_t product[4]) {
    uint64_t high_lo = product[2];
    uint64_t high_hi = product[3];
    uint64_t folded_lo = high_lo;
    uint64_t folded_hi = high_hi;
    uint64_t overflow = 0u;
    uint64_t final_fold;

    folded_lo ^= high_lo << 1u;
    folded_hi ^= (high_hi << 1u) ^ (high_lo >> 63u);
    overflow ^= high_hi >> 63u;

    folded_lo ^= high_lo << 2u;
    folded_hi ^= (high_hi << 2u) ^ (high_lo >> 62u);
    overflow ^= high_hi >> 62u;

    folded_lo ^= high_lo << 7u;
    folded_hi ^= (high_hi << 7u) ^ (high_lo >> 57u);
    overflow ^= high_hi >> 57u;

    final_fold = overflow ^ (overflow << 1u) ^ (overflow << 2u) ^ (overflow << 7u);
    product[0] ^= folded_lo ^ final_fold;
    product[1] ^= folded_hi;
    product[2] = 0u;
    product[3] = 0u;

    high_lo = 0u;
    high_hi = 0u;
    folded_lo = 0u;
    folded_hi = 0u;
    overflow = 0u;
    final_fold = 0u;
}

/*
 * PCLMULQDQ GHASH multiply.  The 128-bit product is assembled using
 * Karatsuba's three carry-less multiplies, then reduced with the fixed
 * polynomial fold above.  There are no secret-indexed tables or data-dependent
 * branches, and the result is byte-for-byte the software GHASH result.
 */
static JS_PCLMUL_HW_TARGET void js_aes_gcm_multiply_pclmul(
    unsigned char value[16],
    const unsigned char hash_subkey[16]
) {
    uint64_t value_words[2];
    uint64_t hash_words[2];
    uint64_t product[4] = {0u, 0u, 0u, 0u};
    uint64_t left_lo;
    uint64_t left_hi;
    uint64_t right_lo;
    uint64_t right_hi;
    __m128i left;
    __m128i right;
    __m128i product00;
    __m128i product11;
    __m128i left_fold;
    __m128i right_fold;
    __m128i product_cross;
    __m128i product_lo;
    __m128i product_hi;

    memcpy(value_words, value, sizeof(value_words));
    memcpy(hash_words, hash_subkey, sizeof(hash_words));
    left_lo = js_gcm_reverse_bits_in_each_byte64(value_words[0]);
    left_hi = js_gcm_reverse_bits_in_each_byte64(value_words[1]);
    right_lo = js_gcm_reverse_bits_in_each_byte64(hash_words[0]);
    right_hi = js_gcm_reverse_bits_in_each_byte64(hash_words[1]);
    left = _mm_set_epi64x((long long)left_hi, (long long)left_lo);
    right = _mm_set_epi64x((long long)right_hi, (long long)right_lo);
    product00 = _mm_clmulepi64_si128(left, right, 0x00);
    product11 = _mm_clmulepi64_si128(left, right, 0x11);
    left_fold = _mm_xor_si128(left, _mm_shuffle_epi32(left, _MM_SHUFFLE(1, 0, 3, 2)));
    right_fold = _mm_xor_si128(right, _mm_shuffle_epi32(right, _MM_SHUFFLE(1, 0, 3, 2)));
    product_cross = _mm_clmulepi64_si128(left_fold, right_fold, 0x00);
    product_cross = _mm_xor_si128(product_cross, product00);
    product_cross = _mm_xor_si128(product_cross, product11);
    product_lo = _mm_xor_si128(product00, _mm_slli_si128(product_cross, 8));
    product_hi = _mm_xor_si128(product11, _mm_srli_si128(product_cross, 8));
    _mm_storeu_si128((__m128i *)(void *)product, product_lo);
    _mm_storeu_si128((__m128i *)(void *)(product + 2u), product_hi);

    js_gcm_reduce_product_fast(product);
    product[0] = js_gcm_reverse_bits_in_each_byte64(product[0]);
    product[1] = js_gcm_reverse_bits_in_each_byte64(product[1]);
    memcpy(value, product, 16u);

    js_vbc4_wipe_volatile(value_words, sizeof(value_words));
    js_vbc4_wipe_volatile(hash_words, sizeof(hash_words));
    js_vbc4_wipe_volatile(product, sizeof(product));
    left = _mm_setzero_si128();
    right = _mm_setzero_si128();
    product00 = _mm_setzero_si128();
    product11 = _mm_setzero_si128();
    left_fold = _mm_setzero_si128();
    right_fold = _mm_setzero_si128();
    product_cross = _mm_setzero_si128();
    product_lo = _mm_setzero_si128();
    product_hi = _mm_setzero_si128();
    left_lo = 0u;
    left_hi = 0u;
    right_lo = 0u;
    right_hi = 0u;
}

static JS_AES_HW_TARGET void js_aes_schedule_encrypt_block_hw(
    const js_aes_schedule *schedule,
    const unsigned char in[16],
    unsigned char out[16]
) {
    __m128i state;
    if (!schedule || !schedule->initialized || !in || !out) return;
    state = _mm_loadu_si128((const __m128i *)(const void *)in);
    state = _mm_xor_si128(state, _mm_loadu_si128((const __m128i *)(const void *)schedule->round_keys));
    for (unsigned int round = 1u; round < schedule->rounds; round++) {
        state = _mm_aesenc_si128(
            state,
            _mm_loadu_si128((const __m128i *)(const void *)(schedule->round_keys + round * 16u)));
    }
    state = _mm_aesenclast_si128(
        state,
        _mm_loadu_si128((const __m128i *)(const void *)(schedule->round_keys + schedule->rounds * 16u)));
    _mm_storeu_si128((__m128i *)(void *)out, state);
    state = _mm_setzero_si128();
}

static int js_aes_hw_self_test(void) {
    static const unsigned char expected128[16] = {
        0x66u, 0xe9u, 0x4bu, 0xd4u, 0xefu, 0x8au, 0x2cu, 0x3bu,
        0x88u, 0x4cu, 0xfau, 0x59u, 0xcau, 0x34u, 0x2bu, 0x2eu
    };
    static const unsigned char key256[32] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
        0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu,
        0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
        0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
    };
    static const unsigned char input256[16] = {
        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
    };
    static const unsigned char expected256[16] = {
        0x8eu, 0xa2u, 0xb7u, 0xcau, 0x51u, 0x67u, 0x45u, 0xbfu,
        0xeau, 0xfcu, 0x49u, 0x90u, 0x4bu, 0x49u, 0x60u, 0x89u
    };
    unsigned char key[16] = {0};
    unsigned char input[16] = {0};
    unsigned char output[16] = {0};
    js_aes_schedule schedule;
    unsigned int diff = 0u;
    memset(&schedule, 0, sizeof(schedule));
    js_aes_expand_key(key, schedule.round_keys);
    schedule.rounds = 10u;
    schedule.initialized = 1u;
    js_aes_schedule_encrypt_block_hw(&schedule, input, output);
    for (size_t i = 0u; i < sizeof(expected128); i++) diff |= (unsigned int)(output[i] ^ expected128[i]);
    js_vbc4_wipe_volatile(output, sizeof(output));
    memset(&schedule, 0, sizeof(schedule));
    js_aes256_expand_key(key256, schedule.round_keys);
    schedule.rounds = 14u;
    schedule.initialized = 1u;
    js_aes_schedule_encrypt_block_hw(&schedule, input256, output);
    for (size_t i = 0u; i < sizeof(expected256); i++) diff |= (unsigned int)(output[i] ^ expected256[i]);
    js_vbc4_wipe_volatile(&schedule, sizeof(schedule));
    js_vbc4_wipe_volatile(output, sizeof(output));
    return diff == 0u;
}
#endif

typedef void (*js_aes_schedule_encrypt_fn)(
    const js_aes_schedule *schedule,
    const unsigned char in[16],
    unsigned char out[16]
);

#if JS_AES_HW_DISPATCH && !defined(JS_CRYPTO_FORCE_SOFTWARE)
static int js_aes_gcm_multiply_hw(unsigned char value[16], const unsigned char hash_subkey[16]);
static int js_aes_ghash_hw_self_test(void);
#endif

static js_runtime_atomic_int js_aes_dispatch_state;
static js_aes_schedule_encrypt_fn js_aes_dispatch = js_aes_schedule_encrypt_block_sw;
static int js_aes_dispatch_hardware = 0;
static int js_aes_dispatch_pclmul = 0;

static void js_aes_dispatch_init(void) {
    int state = js_runtime_atomic_int_load_acquire(&js_aes_dispatch_state);
    if (state == 2) return;
    int expected = 0;
    if (js_runtime_atomic_int_compare_exchange_acq_rel(
            &js_aes_dispatch_state,
            &expected,
            1)) {
#if JS_AES_HW_DISPATCH && !defined(JS_CRYPTO_FORCE_SOFTWARE)
        if (js_aes_runtime_has_pclmul() && js_aes_ghash_hw_self_test()) {
            js_aes_dispatch_pclmul = 1;
        }
        if (js_aes_runtime_has_aes() && js_aes_hw_self_test()) {
            js_aes_dispatch = js_aes_schedule_encrypt_block_hw;
            js_aes_dispatch_hardware = 1;
        }
#endif
        js_runtime_atomic_int_store_release(&js_aes_dispatch_state, 2);
        return;
    }
    while (js_runtime_atomic_int_load_acquire(&js_aes_dispatch_state) != 2) {
        /* Another thread owns one-time capability detection. */
    }
}

static int js_aes_dispatch_uses_hardware(void) {
    js_aes_dispatch_init();
    return js_aes_dispatch_hardware;
}

JS_HIDDEN int js_aes_hardware_available(void) {
    return js_aes_dispatch_uses_hardware();
}

JS_HIDDEN int js_ghash_hardware_available(void) {
    js_aes_dispatch_init();
    return js_aes_dispatch_pclmul;
}

static void js_aes_schedule_encrypt_block(
    const js_aes_schedule *schedule,
    const unsigned char in[16],
    unsigned char out[16]
) {
    js_crypto_metric_increment(&js_crypto_metrics.aes_block_count);
    js_aes_dispatch_init();
    js_aes_dispatch(schedule, in, out);
}

/* Encrypt a bounded batch with one dispatch-state load and one metric update.
 * The dispatch target itself remains immutable after capability self-test; the
 * batch only removes repeated bookkeeping around the existing block primitive. */
static void js_aes_schedule_encrypt_blocks4(
    const js_aes_schedule *schedule,
    const unsigned char inputs[4][16],
    unsigned char outputs[4][16],
    unsigned int count
) {
    if (!schedule || !inputs || !outputs || count == 0u || count > 4u) return;
    js_crypto_metric_add(&js_crypto_metrics.aes_block_count, count);
    js_aes_dispatch_init();
    for (unsigned int lane = 0u; lane < count; lane++) {
        js_aes_dispatch(schedule, inputs[lane], outputs[lane]);
    }
}

static void js_aes_schedule_clear(js_aes_schedule *schedule) {
    if (schedule) js_vbc4_wipe_volatile(schedule, sizeof(*schedule));
}

JS_HIDDEN void js_aes_ctr_xor(
    unsigned char *bytes,
    size_t size,
    const unsigned char *key,
    size_t key_len,
    const unsigned char iv[16]
) {
    unsigned char counter[16] = {0};
    unsigned char counters[4][16] = {{0}};
    unsigned char blocks[4][16] = {{0}};
    size_t takes[4] = {0u};
    js_aes_schedule schedule;
    size_t offset = 0u;
    memset(&schedule, 0, sizeof(schedule));
    if (!bytes || !key || !iv || !js_aes_schedule_init(&schedule, key, key_len)) goto cleanup;
    memcpy(counter, iv, sizeof(counter));
    while (offset < size) {
        unsigned int lane_count = 0u;
        size_t batch_offset = offset;
        while (lane_count < 4u && offset < size) {
            size_t take = size - offset < 16u ? size - offset : 16u;
            memcpy(counters[lane_count], counter, sizeof(counters[lane_count]));
            takes[lane_count] = take;
            offset += take;
            lane_count++;
            js_ctr_inc(counter);
        }
        js_aes_schedule_encrypt_blocks4(&schedule, counters, blocks, lane_count);
        for (unsigned int lane = 0u; lane < lane_count; lane++) {
            for (size_t index = 0u; index < takes[lane]; index++) {
                bytes[batch_offset + index] ^= blocks[lane][index];
            }
            batch_offset += takes[lane];
        }
    }

cleanup:
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(counters, sizeof(counters));
    js_vbc4_wipe_volatile(blocks, sizeof(blocks));
    js_vbc4_wipe_volatile(takes, sizeof(takes));
    js_aes_schedule_clear(&schedule);
}

JS_HIDDEN void js_aes128_ctr_xor(
    unsigned char *bytes,
    size_t size,
    const unsigned char key[16],
    const unsigned char iv[16]
) {
    js_aes_ctr_xor(bytes, size, key, 16u, iv);
}

static void js_aes_gcm_inc32(unsigned char counter[16]) {
    for (int i = 15; i >= 12; i--) if (++counter[i] != 0u) break;
}

/* Decrypt counter-mode payload blocks in a fixed four-lane batch.  The
 * counter state remains private to this operation; every lane is wiped before
 * returning and the caller still performs authentication before invoking this
 * helper. */
static void js_aes_gcm_crypt_payload(
    const js_aes_schedule *schedule,
    unsigned char counter[16],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plain_out
) {
    unsigned char counters[4][16] = {{0}};
    unsigned char streams[4][16] = {{0}};
    size_t offsets[4] = {0u};
    size_t takes[4] = {0u};
    size_t offset = 0u;

    if (!schedule || !counter || (!ciphertext && ciphertext_len != 0u) ||
        (!plain_out && ciphertext_len != 0u)) {
        goto cleanup;
    }
    while (offset < ciphertext_len) {
        unsigned int lane_count = 0u;
        while (lane_count < 4u && offset < ciphertext_len) {
            size_t take = ciphertext_len - offset < 16u ? ciphertext_len - offset : 16u;
            js_aes_gcm_inc32(counter);
            memcpy(counters[lane_count], counter, sizeof(counters[lane_count]));
            offsets[lane_count] = offset;
            takes[lane_count] = take;
            offset += take;
            lane_count++;
        }
        js_aes_schedule_encrypt_blocks4(schedule, counters, streams, lane_count);
        for (unsigned int lane = 0u; lane < lane_count; lane++) {
            for (size_t index = 0u; index < takes[lane]; index++) {
                plain_out[offsets[lane] + index] =
                    (unsigned char)(ciphertext[offsets[lane] + index] ^ streams[lane][index]);
            }
        }
    }

cleanup:
    js_vbc4_wipe_volatile(counters, sizeof(counters));
    js_vbc4_wipe_volatile(streams, sizeof(streams));
    js_vbc4_wipe_volatile(offsets, sizeof(offsets));
    js_vbc4_wipe_volatile(takes, sizeof(takes));
}

static void js_aes_gcm_multiply_software(unsigned char value[16], const unsigned char hash_subkey[16]) {
    unsigned char product[16] = {0};
    unsigned char factor[16];
    memcpy(factor, hash_subkey, sizeof(factor));
    for (unsigned int bit = 0u; bit < 128u; bit++) {
        unsigned char mask = (unsigned char)(0u - ((value[bit / 8u] >> (7u - (bit & 7u))) & 1u));
        unsigned char lsb = (unsigned char)(factor[15] & 1u);
        for (unsigned int i = 0; i < 16u; i++) product[i] ^= (unsigned char)(factor[i] & mask);
        for (int i = 15; i > 0; i--) factor[i] = (unsigned char)((factor[i] >> 1) | (factor[i - 1] << 7));
        factor[0] = (unsigned char)(factor[0] >> 1);
        factor[0] ^= (unsigned char)(0xe1u & (unsigned char)(0u - lsb));
    }
    memcpy(value, product, sizeof(product));
    js_vbc4_wipe_volatile(product, sizeof(product));
    js_vbc4_wipe_volatile(factor, sizeof(factor));
}

#if JS_AES_HW_DISPATCH && !defined(JS_CRYPTO_FORCE_SOFTWARE)
static int js_aes_gcm_multiply_hw(
    unsigned char value[16],
    const unsigned char hash_subkey[16]
) {
    if (!value || !hash_subkey) return 0;
    js_aes_gcm_multiply_pclmul(value, hash_subkey);
    return 1;
}

static int js_aes_ghash_hw_self_test_case(
    const unsigned char input[16],
    const unsigned char hash_subkey[16],
    const unsigned char expected[16]
) {
    unsigned char software[16];
    unsigned char hardware[16];
    unsigned int diff = 0u;
    memcpy(software, input, sizeof(software));
    memcpy(hardware, input, sizeof(hardware));
    js_aes_gcm_multiply_software(software, hash_subkey);
    js_aes_gcm_multiply_pclmul(hardware, hash_subkey);
    for (size_t i = 0u; i < sizeof(hardware); i++) {
        diff |= (unsigned int)(software[i] ^ expected[i]);
        diff |= (unsigned int)(hardware[i] ^ expected[i]);
        diff |= (unsigned int)(software[i] ^ hardware[i]);
    }
    js_vbc4_wipe_volatile(software, sizeof(software));
    js_vbc4_wipe_volatile(hardware, sizeof(hardware));
    return diff == 0u;
}

/*
 * The public known-answer vectors catch byte-order and polynomial mistakes.
 * Add a deterministic, fixed-count corpus so a compiler/intrinsic issue that
 * happens to preserve those vectors cannot enable the hardware dispatch.  The
 * corpus is generated locally, retained only on the stack, and compared with
 * the authoritative constant-time software GHASH implementation.
 */
static uint32_t js_aes_ghash_self_test_next(uint32_t *state) {
    uint32_t value = *state;
    value ^= value << 13u;
    value ^= value >> 17u;
    value ^= value << 5u;
    *state = value;
    return value;
}

static int js_aes_ghash_hw_self_test_randomized(void) {
    unsigned char input[16];
    unsigned char hash_subkey[16];
    unsigned char software[16];
    unsigned char hardware[16];
    uint32_t state = UINT32_C(0x6d2b79f5);
    unsigned int diff = 0u;

    for (unsigned int case_index = 0u; case_index < 128u; case_index++) {
        for (unsigned int index = 0u; index < sizeof(input); index++) {
            input[index] = (unsigned char)(js_aes_ghash_self_test_next(&state) >> ((index & 3u) * 8u));
            hash_subkey[index] = (unsigned char)(js_aes_ghash_self_test_next(&state) >> (((index + 1u) & 3u) * 8u));
        }
        memcpy(software, input, sizeof(software));
        memcpy(hardware, input, sizeof(hardware));
        js_aes_gcm_multiply_software(software, hash_subkey);
        js_aes_gcm_multiply_pclmul(hardware, hash_subkey);
        for (unsigned int index = 0u; index < sizeof(software); index++) {
            diff |= (unsigned int)(software[index] ^ hardware[index]);
        }
    }

    js_vbc4_wipe_volatile(input, sizeof(input));
    js_vbc4_wipe_volatile(hash_subkey, sizeof(hash_subkey));
    js_vbc4_wipe_volatile(software, sizeof(software));
    js_vbc4_wipe_volatile(hardware, sizeof(hardware));
    state = 0u;
    return diff == 0u;
}

static int js_aes_ghash_hw_self_test(void) {
    static const unsigned char input0[16] = {
        0x03u, 0x88u, 0xdau, 0xceu, 0x60u, 0xb6u, 0xa3u, 0x92u,
        0xf3u, 0x28u, 0xc2u, 0xb9u, 0x71u, 0xb2u, 0xfeu, 0x78u
    };
    static const unsigned char hash0[16] = {
        0x66u, 0xe9u, 0x4bu, 0xd4u, 0xefu, 0x8au, 0x2cu, 0x3bu,
        0x88u, 0x4cu, 0xfau, 0x59u, 0xcau, 0x34u, 0x2bu, 0x2eu
    };
    static const unsigned char expected0[16] = {
        0x5eu, 0x2eu, 0xc7u, 0x46u, 0x91u, 0x70u, 0x62u, 0x88u,
        0x2cu, 0x85u, 0xb0u, 0x68u, 0x53u, 0x53u, 0xdeu, 0xb7u
    };
    static const unsigned char input1[16] = {
        0x29u, 0xbeu, 0xe1u, 0xd6u, 0x52u, 0x49u, 0xf1u, 0xe9u,
        0xb3u, 0xdbu, 0x87u, 0x3eu, 0x24u, 0x0du, 0x06u, 0x47u
    };
    static const unsigned char hash1[16] = {
        0x23u, 0x84u, 0x6cu, 0xaeu, 0x90u, 0xf1u, 0xbbu, 0xebu,
        0xa6u, 0x3cu, 0x0cu, 0x99u, 0x5eu, 0x1cu, 0xb7u, 0xdeu
    };
    static const unsigned char expected1[16] = {
        0xdeu, 0x38u, 0x03u, 0x1eu, 0xf2u, 0xe3u, 0xcau, 0x2fu,
        0x87u, 0x65u, 0xd0u, 0x94u, 0x69u, 0x53u, 0xceu, 0x23u
    };
    return js_aes_ghash_hw_self_test_case(input0, hash0, expected0) &&
        js_aes_ghash_hw_self_test_case(input1, hash1, expected1) &&
        js_aes_ghash_hw_self_test_randomized();
}
#endif

static void js_aes_gcm_multiply(unsigned char value[16], const unsigned char hash_subkey[16]) {
#if JS_AES_HW_DISPATCH && !defined(JS_CRYPTO_FORCE_SOFTWARE)
    if (js_ghash_hardware_available() && js_aes_gcm_multiply_hw(value, hash_subkey)) return;
#endif
    js_aes_gcm_multiply_software(value, hash_subkey);
}

static void js_aes_gcm_hash_block(unsigned char state[16], const unsigned char hash_subkey[16], const unsigned char block[16]) {
    js_crypto_metric_increment(&js_crypto_metrics.ghash_block_count);
    for (unsigned int i = 0; i < 16u; i++) state[i] ^= block[i];
    js_aes_gcm_multiply(state, hash_subkey);
}

static void js_aes_gcm_hash_update(unsigned char state[16], const unsigned char hash_subkey[16], const unsigned char *data, size_t len) {
    unsigned char partial[16] = {0};
    while (len >= 16u) {
        js_aes_gcm_hash_block(state, hash_subkey, data);
        data += 16u;
        len -= 16u;
    }
    if (len != 0u) {
        memcpy(partial, data, len);
        js_aes_gcm_hash_block(state, hash_subkey, partial);
    }
    js_vbc4_wipe_volatile(partial, sizeof(partial));
}

static void js_aes_gcm_store_be64(unsigned char out[8], uint64_t value) {
    for (unsigned int i = 0; i < 8u; i++) out[7u - i] = (unsigned char)(value >> (i * 8u));
}

static int js_aes_gcm_consttime_equal(const unsigned char *left, const unsigned char *right, size_t len) {
    unsigned int diff = 0u;
    if (!left || !right) return 0;
    for (size_t i = 0; i < len; i++) diff |= (unsigned int)(left[i] ^ right[i]);
    return diff == 0u;
}

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
) {
    unsigned char hash_subkey[16] = {0}, ghash[16] = {0}, j0[16] = {0}, counter[16] = {0};
    unsigned char tag_mask[16] = {0}, calculated_tag[16] = {0}, lengths[16] = {0};
    js_aes_schedule schedule;
    size_t ciphertext_len = 0u;
    size_t wipe_len = 0u;
    int ok = 0;
    memset(&schedule, 0, sizeof(schedule));
    js_crypto_metric_increment(&js_crypto_metrics.auth_check_count);
    js_runtime_metrics_note_structure_check();
    js_runtime_metrics_note_length_check();
    if (!ciphertext_and_tag || ciphertext_and_tag_len < 16u) {
        js_crypto_metric_increment(&js_crypto_metrics.auth_failure_count);
        goto cleanup;
    }
    ciphertext_len = ciphertext_and_tag_len - 16u;
    js_runtime_metrics_note_length_check();
    if (aad_len > (size_t)(UINT64_MAX / 8u) || ciphertext_len > (size_t)(UINT64_MAX / 8u)) goto cleanup;
    if ((uint64_t)(ciphertext_len / 16u) + (ciphertext_len % 16u != 0u ? 1u : 0u) > (uint64_t)UINT32_MAX - 1u) goto cleanup;
    if (plain_out && ciphertext_len != 0u) wipe_len = ciphertext_len;
    if (!nonce || (!aad && aad_len != 0u) || (!plain_out && ciphertext_len != 0u)) goto cleanup;

    memcpy(j0, nonce, 12u);
    j0[15] = 1u;
    if (!js_aes_schedule_init_lanes(
            &schedule,
            lane0,
            lane1,
            lane2,
            lane3,
            lane4,
            lane5,
            lane6,
            lane7)) goto cleanup;
    js_aes_schedule_encrypt_block(&schedule, (const unsigned char[16]){0}, hash_subkey);
    js_aes_gcm_hash_update(ghash, hash_subkey, aad, aad_len);
    js_aes_gcm_hash_update(ghash, hash_subkey, ciphertext_and_tag, ciphertext_len);
    js_aes_gcm_store_be64(lengths, (uint64_t)aad_len * 8u);
    js_aes_gcm_store_be64(lengths + 8u, (uint64_t)ciphertext_len * 8u);
    js_aes_gcm_hash_block(ghash, hash_subkey, lengths);
    js_aes_schedule_encrypt_block(&schedule, j0, tag_mask);
    for (unsigned int i = 0; i < 16u; i++) calculated_tag[i] = (unsigned char)(ghash[i] ^ tag_mask[i]);
    js_crypto_metric_increment(&js_crypto_metrics.tag_check_count);
    ok = js_aes_gcm_consttime_equal(calculated_tag, ciphertext_and_tag + ciphertext_len, sizeof(calculated_tag));
    if (!ok) {
        js_crypto_metric_increment(&js_crypto_metrics.auth_failure_count);
        goto cleanup;
    }

    memcpy(counter, j0, sizeof(counter));
    js_aes_gcm_crypt_payload(&schedule, counter, ciphertext_and_tag, ciphertext_len, plain_out);

cleanup:
    if (!ok && plain_out && wipe_len != 0u) js_vbc4_wipe_volatile(plain_out, wipe_len);
    js_vbc4_wipe_volatile(hash_subkey, sizeof(hash_subkey));
    js_vbc4_wipe_volatile(ghash, sizeof(ghash));
    js_vbc4_wipe_volatile(j0, sizeof(j0));
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(tag_mask, sizeof(tag_mask));
    js_vbc4_wipe_volatile(calculated_tag, sizeof(calculated_tag));
    js_vbc4_wipe_volatile(lengths, sizeof(lengths));
    js_aes_schedule_clear(&schedule);
    js_vbc4_wipe_volatile(&lane0, sizeof(lane0));
    js_vbc4_wipe_volatile(&lane1, sizeof(lane1));
    js_vbc4_wipe_volatile(&lane2, sizeof(lane2));
    js_vbc4_wipe_volatile(&lane3, sizeof(lane3));
    js_vbc4_wipe_volatile(&lane4, sizeof(lane4));
    js_vbc4_wipe_volatile(&lane5, sizeof(lane5));
    js_vbc4_wipe_volatile(&lane6, sizeof(lane6));
    js_vbc4_wipe_volatile(&lane7, sizeof(lane7));
    return ok;
}

JS_HIDDEN int js_aes_gcm_decrypt(
    const unsigned char *key,
    size_t key_len,
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *ciphertext_and_tag,
    size_t ciphertext_and_tag_len,
    unsigned char *plain_out
) {
    unsigned char hash_subkey[16] = {0}, ghash[16] = {0}, j0[16] = {0}, counter[16] = {0};
    unsigned char tag_mask[16] = {0}, calculated_tag[16] = {0}, lengths[16] = {0};
    js_aes_schedule schedule;
    size_t ciphertext_len = 0u;
    size_t wipe_len = 0u;
    int ok = 0;
    memset(&schedule, 0, sizeof(schedule));
    js_crypto_metric_increment(&js_crypto_metrics.auth_check_count);
    js_runtime_metrics_note_structure_check();
    js_runtime_metrics_note_length_check();
    if (!ciphertext_and_tag || ciphertext_and_tag_len < 16u) {
        js_crypto_metric_increment(&js_crypto_metrics.auth_failure_count);
        goto cleanup;
    }
    ciphertext_len = ciphertext_and_tag_len - 16u;
    js_runtime_metrics_note_length_check();
    if (aad_len > (size_t)(UINT64_MAX / 8u) || ciphertext_len > (size_t)(UINT64_MAX / 8u)) goto cleanup;
    if ((uint64_t)(ciphertext_len / 16u) + (ciphertext_len % 16u != 0u ? 1u : 0u) > (uint64_t)UINT32_MAX - 1u) goto cleanup;
    if (plain_out && ciphertext_len != 0u) wipe_len = ciphertext_len;
    if (!key || (key_len != 16u && key_len != 32u) || !nonce || (!aad && aad_len != 0u) ||
        (!plain_out && ciphertext_len != 0u)) goto cleanup;

    memcpy(j0, nonce, 12u);
    j0[15] = 1u;
    if (!js_aes_schedule_init(&schedule, key, key_len)) goto cleanup;
    js_aes_schedule_encrypt_block(&schedule, (const unsigned char[16]){0}, hash_subkey);
    js_aes_gcm_hash_update(ghash, hash_subkey, aad, aad_len);
    js_aes_gcm_hash_update(ghash, hash_subkey, ciphertext_and_tag, ciphertext_len);
    js_aes_gcm_store_be64(lengths, (uint64_t)aad_len * 8u);
    js_aes_gcm_store_be64(lengths + 8u, (uint64_t)ciphertext_len * 8u);
    js_aes_gcm_hash_block(ghash, hash_subkey, lengths);
    js_aes_schedule_encrypt_block(&schedule, j0, tag_mask);
    for (unsigned int i = 0; i < 16u; i++) calculated_tag[i] = (unsigned char)(ghash[i] ^ tag_mask[i]);
    js_crypto_metric_increment(&js_crypto_metrics.tag_check_count);
    ok = js_aes_gcm_consttime_equal(calculated_tag, ciphertext_and_tag + ciphertext_len, sizeof(calculated_tag));
    if (!ok) {
        js_crypto_metric_increment(&js_crypto_metrics.auth_failure_count);
        goto cleanup;
    }

    memcpy(counter, j0, sizeof(counter));
    js_aes_gcm_crypt_payload(&schedule, counter, ciphertext_and_tag, ciphertext_len, plain_out);

cleanup:
    if (!ok && plain_out && wipe_len != 0u) js_vbc4_wipe_volatile(plain_out, wipe_len);
    js_vbc4_wipe_volatile(hash_subkey, sizeof(hash_subkey));
    js_vbc4_wipe_volatile(ghash, sizeof(ghash));
    js_vbc4_wipe_volatile(j0, sizeof(j0));
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(tag_mask, sizeof(tag_mask));
    js_vbc4_wipe_volatile(calculated_tag, sizeof(calculated_tag));
    js_vbc4_wipe_volatile(lengths, sizeof(lengths));
    js_aes_schedule_clear(&schedule);
    return ok;
}
