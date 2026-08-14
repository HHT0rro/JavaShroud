#include "js_jni_runtime.h"
#include "js_antidebug.h"
#include "js_protected_section.h"
#include "js_vm_core.h"
#include "js_vm_resource.h"
#include "js_crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define JS_SHELL_MANUAL_MAP_RESERVED ((void *)(uintptr_t)0x4A5353484D4D4150ULL)

static volatile int js_jni_runtime_manual_mapped_shell = 0;

JS_HIDDEN js_jni_cache_state js_jni_cache;

extern jint JNICALL jsn_k0(JNIEnv* env, jclass clazz, jstring platform);
extern jint JNICALL jsn_k1(JNIEnv* env, jclass clazz, jbyteArray data, jbyteArray expected_mac);
extern jint JNICALL jsn_k3(JNIEnv* env, jclass clazz);
extern jbyteArray JNICALL jsn_k4(JNIEnv* env, jclass clazz, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr);
extern jstring JNICALL jsn_k5(JNIEnv* env, jclass clazz);
extern jlong JNICALL jsn_k6(JNIEnv* env, jclass clazz);
JS_HIDDEN jboolean JNICALL jsn_k7(JNIEnv *env, jclass cls, jbyteArray material);
JS_HIDDEN jboolean JNICALL jsn_k11(JNIEnv *env, jclass cls);
JS_HIDDEN void JNICALL jsn_k12(JNIEnv *env, jclass cls);
JS_HIDDEN void JNICALL jsn_k9(JNIEnv *env, jclass cls, jbyteArray preload_index, jbyteArray commitments, jbyteArray startup_nonce);
JS_HIDDEN jbyteArray JNICALL jsn_k10(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length);
JS_HIDDEN jbyteArray JNICALL jsn_k14(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jbyteArray nonceArr, jbyteArray ciphertextArr, jbyteArray aadArr, jint keyLength);
JS_HIDDEN jstring JNICALL jsn_k15(JNIEnv *env, jclass cls, jbyteArray valueArr);
JS_HIDDEN jbyteArray JNICALL jsn_k13(JNIEnv *env, jclass cls, jbyteArray encoded);
JS_HIDDEN void JNICALL jsn_r0(JNIEnv *env, jclass cls, jstring jdl, jstring jresp);
JS_HIDDEN void JNICALL jsn_r1(JNIEnv *env, jclass cls, jstring jdm, jstring jresp);
JS_HIDDEN void JNICALL jsn_r2(JNIEnv *env, jclass cls, jstring jresp);
JS_HIDDEN void JNICALL jsn_r3(JNIEnv *env, jclass cls, jstring jpl);
JS_HIDDEN void JNICALL jsn_r4(JNIEnv *env, jclass cls, jstring jpl, jclass ownerClass);
JS_HIDDEN jstring JNICALL jsn_r11(JNIEnv *env, jclass cls, jbyteArray encodedBytes);
JS_HIDDEN jstring JNICALL jsn_r12(JNIEnv *env, jclass cls, jstring encodedB64);
JS_HIDDEN jstring JNICALL jsn_r13(JNIEnv *env, jclass cls, jstring encoded);
JS_HIDDEN jstring JNICALL jsn_r16(JNIEnv *env, jclass cls, jstring bindingSource, jstring salt, jstring expectedFingerprint);
JS_HIDDEN void JNICALL jsn_r17(JNIEnv *env, jclass cls, jstring expectedToken, jstring bindingSource, jstring salt, jstring expectedFingerprint);
JS_HIDDEN jstring JNICALL jsn_r18(JNIEnv *env, jclass cls);
JS_HIDDEN jobject JNICALL jsn_r20(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args);
JS_HIDDEN jbyteArray JNICALL jsn_r21(JNIEnv *env, jclass cls, jbyteArray payload, jint seed, jint flags, jlong classIdentityHigh, jlong classIdentityLow);
JS_HIDDEN jobject JNICALL jsn_r22(JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args);
JS_HIDDEN void JNICALL jsn_r23(JNIEnv *env, jclass cls, jlong entryToken);
JS_HIDDEN void JNICALL jsn_r24(JNIEnv *env, jclass cls, jlong entryToken, jint arg0);
JS_HIDDEN jint JNICALL jsn_r25(JNIEnv *env, jclass cls, jlong entryToken);
JS_HIDDEN jint JNICALL jsn_r26(JNIEnv *env, jclass cls, jlong entryToken, jint arg0);

/* AKEN bridge entry points are defined below the protected-runtime lifecycle
 * helpers.  Keep explicit prototypes here so C99 builds do not infer an
 * external declaration before the later static definitions. */
static int js_protected_runtime_enter(JNIEnv *env);
static int js_protected_runtime_leave(JNIEnv *env);

static void js_aken_bridge_unavailable(JNIEnv *env, const char *purpose) {
    if (!env || (*env)->ExceptionCheck(env)) return;
    jclass failure = (*env)->FindClass(env, "java/lang/SecurityException");
    if (!failure || (*env)->ExceptionCheck(env)) return;
    (*env)->ThrowNew(env, failure, purpose);
    (*env)->DeleteLocalRef(env, failure);
}

static int js_aken_bridge_request_is_valid(JNIEnv *env, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof) {
    if (!env || !encoded_handle || !call_site_proof || page_index < 0 ||
        (*env)->GetArrayLength(env, encoded_handle) != 24 ||
        (*env)->GetArrayLength(env, call_site_proof) <= 0 ||
        (*env)->GetArrayLength(env, call_site_proof) > 4096) {
        js_aken_bridge_unavailable(env, "AKEN page request is invalid");
        return 0;
    }
    if ((*env)->ExceptionCheck(env)) return 0;
    return 1;
}

/*
 * TODO(AKEN-v4): typed JNI currently receives only handle/page/proof/args.
 * Once the resource-specific locator produces a verified descriptor envelope,
 * pass its current-page binding and seven evaluator fragments to
 * js_aken_evaluator_recover_dek().  Do not feed arbitrary resource byte arrays
 * into this primitive and do not reintroduce a legacy generic decode fallback.
 */
#define JS_AKEN_EVALUATOR_SHAPE_VERSION 2u
#define JS_AKEN_EVALUATOR_SALT_SIZE 16u
#define JS_AKEN_EVALUATOR_TAG_SIZE 8u
#define JS_AKEN_EVALUATOR_ENCODED_SHARE_OFFSET 1u
#define JS_AKEN_EVALUATOR_COMMITMENT_SHARE_OFFSET (JS_AKEN_EVALUATOR_ENCODED_SHARE_OFFSET + JS_AKEN_EVALUATOR_STATE_WIDTH)
#define JS_AKEN_EVALUATOR_SALT_OFFSET (JS_AKEN_EVALUATOR_COMMITMENT_SHARE_OFFSET + JS_AKEN_EVALUATOR_STATE_WIDTH)
#define JS_AKEN_EVALUATOR_TAG_OFFSET (JS_AKEN_EVALUATOR_SALT_OFFSET + JS_AKEN_EVALUATOR_SALT_SIZE)
#define JS_AKEN_EVALUATOR_MIN_SHAPE_SIZE (JS_AKEN_EVALUATOR_TAG_OFFSET + JS_AKEN_EVALUATOR_TAG_SIZE)
#define JS_AKEN_EVALUATOR_MIN_CALL_TOKEN_SIZE 32u
#define JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES 4096u
#define JS_AKEN_EVALUATOR_MAX_LOGICAL_IDENTITY_BYTES (64u * 1024u)

static const unsigned char JS_AKEN_EVALUATOR_MASK_DOMAIN[] = "AKEN-v4-evaluator-state-mask-v1";
static const unsigned char JS_AKEN_EVALUATOR_TAG_DOMAIN[] = "AKEN-v4-evaluator-state-tag-v1";

static void js_aken_evaluator_update_u32be(js_sha256_ctx *ctx, uint32_t value) {
    const unsigned char bytes[4] = {
        (unsigned char)(value >> 24),
        (unsigned char)(value >> 16),
        (unsigned char)(value >> 8),
        (unsigned char)value,
    };
    js_sha256_update(ctx, bytes, (int)sizeof(bytes));
}

static int js_aken_evaluator_update_framed(js_sha256_ctx *ctx, const unsigned char *value, size_t value_len) {
    if (!ctx || value_len > (size_t)INT_MAX || (value_len != 0u && !value)) return 0;
    js_aken_evaluator_update_u32be(ctx, (uint32_t)value_len);
    if (value_len != 0u) js_sha256_update(ctx, value, (int)value_len);
    return 1;
}

static int js_aken_evaluator_target_size_is_valid(uint8_t kind_id, jint target_size) {
    switch (kind_id) {
        case 1: return target_size == 512 || target_size == 768 || target_size == 1024 || target_size == 1536 || target_size == 2048;
        case 2: return target_size == 128 || target_size == 192 || target_size == 256 || target_size == 384 || target_size == 512;
        case 3: return target_size == 512 || target_size == 1024 || target_size == 1536 || target_size == 2048;
        case 4: return target_size == 1024 || target_size == 1536 || target_size == 2048 || target_size == 3072;
        default: return 0;
    }
}

static int js_aken_evaluator_binding_is_valid(const js_aken_evaluator_binding *binding) {
    if (!binding || binding->kind_id < 1u || binding->kind_id > 4u || binding->page_index < 0 ||
        !js_aken_evaluator_target_size_is_valid(binding->kind_id, binding->target_size)) return 0;
    if (!binding->logical_identity || binding->logical_identity_len == 0u ||
        binding->logical_identity_len > JS_AKEN_EVALUATOR_MAX_LOGICAL_IDENTITY_BYTES) return 0;
    if (!binding->codec_variant || binding->codec_variant_len == 0u ||
        binding->codec_variant_len > JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES) return 0;
    if (!binding->layout_variant || binding->layout_variant_len == 0u ||
        binding->layout_variant_len > JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES) return 0;
    if (!binding->encoded_handle || binding->encoded_handle_len != 24u ||
        !binding->locator_token || binding->locator_token_len != 16u ||
        !binding->artifact_commitment || binding->artifact_commitment_len != JS_AKEN_EVALUATOR_STATE_WIDTH) return 0;
    return 1;
}

static int js_aken_evaluator_fragment_is_valid(const js_aken_evaluator_fragment *fragment) {
    unsigned char seen[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    int ok = 0;
    if (!fragment || fragment->ordinal < 0 || fragment->ordinal >= (jint)JS_AKEN_EVALUATOR_FRAGMENT_COUNT ||
        fragment->family < 0 || fragment->family >= 16 || !fragment->shape ||
        fragment->shape_len < JS_AKEN_EVALUATOR_MIN_SHAPE_SIZE ||
        fragment->shape_len > JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES ||
        fragment->shape[0] != JS_AKEN_EVALUATOR_SHAPE_VERSION || !fragment->call_token ||
        fragment->call_token_len < JS_AKEN_EVALUATOR_MIN_CALL_TOKEN_SIZE ||
        fragment->call_token_len > JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES ||
        !fragment->table_permutation || fragment->table_permutation_len != JS_AKEN_EVALUATOR_STATE_WIDTH) goto cleanup;
    for (size_t index = 0; index < JS_AKEN_EVALUATOR_STATE_WIDTH; index++) {
        uint32_t value = fragment->table_permutation[index];
        if (value >= JS_AKEN_EVALUATOR_STATE_WIDTH || seen[value]) goto cleanup;
        seen[value] = 1u;
    }
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(seen, sizeof(seen));
    return ok;
}

static int js_aken_evaluator_graph_is_valid(const js_aken_evaluator_fragment *fragments, size_t fragment_count) {
    unsigned char seen[JS_AKEN_EVALUATOR_FRAGMENT_COUNT] = {0};
    int ok = 0;
    if (!fragments || fragment_count != JS_AKEN_EVALUATOR_FRAGMENT_COUNT) goto cleanup;
    for (size_t index = 0; index < fragment_count; index++) {
        const js_aken_evaluator_fragment *fragment = &fragments[index];
        if (!js_aken_evaluator_fragment_is_valid(fragment) || seen[(size_t)fragment->ordinal]) goto cleanup;
        seen[(size_t)fragment->ordinal] = 1u;
    }
    for (size_t ordinal = 0; ordinal < JS_AKEN_EVALUATOR_FRAGMENT_COUNT; ordinal++) {
        if (!seen[ordinal]) goto cleanup;
    }
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(seen, sizeof(seen));
    return ok;
}

static int js_aken_evaluator_update_binding(js_sha256_ctx *ctx, const js_aken_evaluator_binding *binding) {
    const unsigned char kind = binding ? binding->kind_id : 0u;
    if (!ctx || !js_aken_evaluator_binding_is_valid(binding)) return 0;
    js_sha256_update(ctx, &kind, 1);
    if (!js_aken_evaluator_update_framed(ctx, binding->logical_identity, binding->logical_identity_len)) return 0;
    js_aken_evaluator_update_u32be(ctx, (uint32_t)binding->page_index);
    js_aken_evaluator_update_u32be(ctx, (uint32_t)binding->target_size);
    if (!js_aken_evaluator_update_framed(ctx, binding->codec_variant, binding->codec_variant_len)) return 0;
    if (!js_aken_evaluator_update_framed(ctx, binding->layout_variant, binding->layout_variant_len)) return 0;
    if (!js_aken_evaluator_update_framed(ctx, binding->encoded_handle, binding->encoded_handle_len)) return 0;
    return js_aken_evaluator_update_framed(ctx, binding->locator_token, binding->locator_token_len);
}

static int js_aken_evaluator_mask_for(
    const js_aken_evaluator_binding *binding,
    const js_aken_evaluator_fragment *fragment,
    const unsigned char salt[JS_AKEN_EVALUATOR_SALT_SIZE],
    unsigned char out_mask[JS_AKEN_EVALUATOR_STATE_WIDTH]
) {
    js_sha256_ctx ctx;
    int ok = 0;
    if (!binding || !fragment || !salt || !out_mask) return 0;
    js_vbc4_wipe_volatile(out_mask, JS_AKEN_EVALUATOR_STATE_WIDTH);
    memset(&ctx, 0, sizeof(ctx));
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, JS_AKEN_EVALUATOR_MASK_DOMAIN, (int)(sizeof(JS_AKEN_EVALUATOR_MASK_DOMAIN) - 1u));
    if (!js_aken_evaluator_update_binding(&ctx, binding)) goto cleanup;
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)fragment->ordinal);
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)fragment->family);
    if (!js_aken_evaluator_update_framed(&ctx, fragment->call_token, fragment->call_token_len) ||
        !js_aken_evaluator_update_framed(&ctx, salt, JS_AKEN_EVALUATOR_SALT_SIZE)) goto cleanup;
    js_sha256_final(&ctx, out_mask);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    if (!ok) js_vbc4_wipe_volatile(out_mask, JS_AKEN_EVALUATOR_STATE_WIDTH);
    return ok;
}

static int js_aken_evaluator_tag_for(
    const js_aken_evaluator_binding *binding,
    const js_aken_evaluator_fragment *fragment,
    const unsigned char encoded_share[JS_AKEN_EVALUATOR_STATE_WIDTH],
    const unsigned char artifact_commitment_share[JS_AKEN_EVALUATOR_STATE_WIDTH],
    const unsigned char salt[JS_AKEN_EVALUATOR_SALT_SIZE],
    unsigned char out_tag[JS_AKEN_EVALUATOR_STATE_WIDTH]
) {
    js_sha256_ctx ctx;
    int ok = 0;
    if (!binding || !fragment || !encoded_share || !artifact_commitment_share || !salt || !out_tag) return 0;
    js_vbc4_wipe_volatile(out_tag, JS_AKEN_EVALUATOR_STATE_WIDTH);
    memset(&ctx, 0, sizeof(ctx));
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, JS_AKEN_EVALUATOR_TAG_DOMAIN, (int)(sizeof(JS_AKEN_EVALUATOR_TAG_DOMAIN) - 1u));
    if (!js_aken_evaluator_update_binding(&ctx, binding)) goto cleanup;
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)fragment->ordinal);
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)fragment->family);
    if (!js_aken_evaluator_update_framed(&ctx, fragment->call_token, fragment->call_token_len)) goto cleanup;
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)fragment->table_permutation_len);
    for (size_t index = 0; index < fragment->table_permutation_len; index++) {
        js_aken_evaluator_update_u32be(&ctx, fragment->table_permutation[index]);
    }
    if (!js_aken_evaluator_update_framed(&ctx, encoded_share, JS_AKEN_EVALUATOR_STATE_WIDTH) ||
        !js_aken_evaluator_update_framed(&ctx, artifact_commitment_share, JS_AKEN_EVALUATOR_STATE_WIDTH) ||
        !js_aken_evaluator_update_framed(&ctx, salt, JS_AKEN_EVALUATOR_SALT_SIZE)) goto cleanup;
    js_sha256_final(&ctx, out_tag);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    if (!ok) js_vbc4_wipe_volatile(out_tag, JS_AKEN_EVALUATOR_STATE_WIDTH);
    return ok;
}

static int js_aken_evaluator_constant_time_equal(
    const unsigned char *expected,
    const unsigned char *actual,
    size_t length
) {
    unsigned int diff = 0u;
    if (!expected || !actual) return 0;
    for (size_t index = 0; index < length; index++) {
        diff |= (unsigned int)(expected[index] ^ actual[index]);
    }
    return diff == 0u;
}

static int js_aken_evaluator_tag_matches(
    const unsigned char expected[JS_AKEN_EVALUATOR_TAG_SIZE],
    const unsigned char actual[JS_AKEN_EVALUATOR_STATE_WIDTH]
) {
    return js_aken_evaluator_constant_time_equal(expected, actual, JS_AKEN_EVALUATOR_TAG_SIZE);
}

static unsigned int js_aken_evaluator_rol8(unsigned int value, unsigned int shift) {
    return ((value << shift) | (value >> (8u - shift))) & 0xFFu;
}

static unsigned int js_aken_evaluator_ror8(unsigned int value, unsigned int shift) {
    return ((value >> shift) | (value << (8u - shift))) & 0xFFu;
}

static unsigned char js_aken_evaluator_inverse(unsigned char value, unsigned char mask, jint family, unsigned int index) {
    const unsigned int value_u = value;
    const unsigned int mask_u = mask;
    const unsigned int twist = ((mask_u >> 3) + (unsigned int)family + index) & 0xFFu;
    const unsigned int rotation = ((mask_u ^ (unsigned int)family ^ index) & 7u) + 1u;
    switch (family) {
        case 0: return (unsigned char)(value_u ^ mask_u);
        case 1: return (unsigned char)((value_u - mask_u) & 0xFFu);
        case 2: return (unsigned char)((value_u + mask_u) & 0xFFu);
        case 3: return (unsigned char)(js_aken_evaluator_ror8(value_u, rotation) ^ mask_u);
        case 4: return (unsigned char)(js_aken_evaluator_rol8(value_u, rotation) ^ mask_u);
        case 5: return (unsigned char)(((value_u ^ 0xA5u) - mask_u) & 0xFFu);
        case 6: return (unsigned char)(((value_u - mask_u) ^ 0xA5u) & 0xFFu);
        case 7: return (unsigned char)((js_aken_evaluator_ror8(value_u ^ mask_u, rotation) - twist) & 0xFFu);
        case 8: return (unsigned char)((js_aken_evaluator_rol8(value_u ^ mask_u, rotation) + twist) & 0xFFu);
        case 9: return (unsigned char)(((value_u - twist) ^ mask_u) & 0xFFu);
        case 10: return (unsigned char)(((value_u ^ twist) - mask_u) & 0xFFu);
        case 11: return (unsigned char)(js_aken_evaluator_ror8(value_u ^ mask_u, rotation) ^ twist);
        case 12: return (unsigned char)(js_aken_evaluator_rol8(value_u ^ mask_u, rotation) ^ twist);
        case 13: return (unsigned char)(((value_u ^ 0x5Au) + mask_u) & 0xFFu);
        case 14: return (unsigned char)(((value_u + mask_u) ^ 0x5Au) & 0xFFu);
        case 15: return (unsigned char)(js_aken_evaluator_ror8(value_u, rotation) ^ mask_u ^ twist);
        default: return 0u;
    }
}

static int js_aken_evaluator_recover_fragment(
    const js_aken_evaluator_binding *binding,
    const js_aken_evaluator_fragment *fragment,
    unsigned char out_share[JS_AKEN_EVALUATOR_STATE_WIDTH],
    unsigned char out_artifact_commitment_share[JS_AKEN_EVALUATOR_STATE_WIDTH]
) {
    unsigned char encoded_share[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char artifact_commitment_share[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char salt[JS_AKEN_EVALUATOR_SALT_SIZE] = {0};
    unsigned char expected_tag[JS_AKEN_EVALUATOR_TAG_SIZE] = {0};
    unsigned char actual_tag[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char mask[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char transformed[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    int ok = 0;
    if (!binding || !fragment || !out_share || !out_artifact_commitment_share || !js_aken_evaluator_fragment_is_valid(fragment)) goto cleanup;
    js_vbc4_wipe_volatile(out_share, JS_AKEN_EVALUATOR_STATE_WIDTH);
    js_vbc4_wipe_volatile(out_artifact_commitment_share, JS_AKEN_EVALUATOR_STATE_WIDTH);
    memcpy(encoded_share, fragment->shape + JS_AKEN_EVALUATOR_ENCODED_SHARE_OFFSET, sizeof(encoded_share));
    memcpy(artifact_commitment_share, fragment->shape + JS_AKEN_EVALUATOR_COMMITMENT_SHARE_OFFSET, sizeof(artifact_commitment_share));
    memcpy(salt, fragment->shape + JS_AKEN_EVALUATOR_SALT_OFFSET, sizeof(salt));
    memcpy(expected_tag, fragment->shape + JS_AKEN_EVALUATOR_TAG_OFFSET, sizeof(expected_tag));
    if (!js_aken_evaluator_mask_for(binding, fragment, salt, mask) ||
        !js_aken_evaluator_tag_for(binding, fragment, encoded_share, artifact_commitment_share, salt, actual_tag) ||
        !js_aken_evaluator_tag_matches(expected_tag, actual_tag)) goto cleanup;
    for (size_t index = 0; index < JS_AKEN_EVALUATOR_STATE_WIDTH; index++) {
        transformed[fragment->table_permutation[index]] = encoded_share[index];
    }
    for (unsigned int index = 0; index < JS_AKEN_EVALUATOR_STATE_WIDTH; index++) {
        out_share[index] = js_aken_evaluator_inverse(transformed[index], mask[index], fragment->family, index);
    }
    memcpy(out_artifact_commitment_share, artifact_commitment_share, JS_AKEN_EVALUATOR_STATE_WIDTH);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(encoded_share, sizeof(encoded_share));
    js_vbc4_wipe_volatile(artifact_commitment_share, sizeof(artifact_commitment_share));
    js_vbc4_wipe_volatile(salt, sizeof(salt));
    js_vbc4_wipe_volatile(expected_tag, sizeof(expected_tag));
    js_vbc4_wipe_volatile(actual_tag, sizeof(actual_tag));
    js_vbc4_wipe_volatile(mask, sizeof(mask));
    js_vbc4_wipe_volatile(transformed, sizeof(transformed));
    if (!ok && out_share) js_vbc4_wipe_volatile(out_share, JS_AKEN_EVALUATOR_STATE_WIDTH);
    if (!ok && out_artifact_commitment_share) js_vbc4_wipe_volatile(out_artifact_commitment_share, JS_AKEN_EVALUATOR_STATE_WIDTH);
    return ok;
}

JS_HIDDEN int js_aken_evaluator_recover_dek(
    const js_aken_evaluator_binding *binding,
    const js_aken_evaluator_fragment *fragments,
    size_t fragment_count,
    unsigned char out_dek[JS_AKEN_EVALUATOR_STATE_WIDTH]
) {
    unsigned char share[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char artifact_commitment_share[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char reconstructed_artifact_commitment[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    int ok = 0;
    if (!out_dek) goto cleanup;
    js_vbc4_wipe_volatile(out_dek, JS_AKEN_EVALUATOR_STATE_WIDTH);
    if (!js_aken_evaluator_binding_is_valid(binding) || !js_aken_evaluator_graph_is_valid(fragments, fragment_count)) goto cleanup;
    for (size_t fragment_index = 0; fragment_index < JS_AKEN_EVALUATOR_FRAGMENT_COUNT; fragment_index++) {
        if (!js_aken_evaluator_recover_fragment(binding, &fragments[fragment_index], share, artifact_commitment_share)) goto cleanup;
        for (size_t byte_index = 0; byte_index < JS_AKEN_EVALUATOR_STATE_WIDTH; byte_index++) {
            out_dek[byte_index] ^= share[byte_index];
            reconstructed_artifact_commitment[byte_index] ^= artifact_commitment_share[byte_index];
        }
        js_vbc4_wipe_volatile(share, sizeof(share));
        js_vbc4_wipe_volatile(artifact_commitment_share, sizeof(artifact_commitment_share));
    }
    if (!js_aken_evaluator_constant_time_equal(
            reconstructed_artifact_commitment,
            binding->artifact_commitment,
            JS_AKEN_EVALUATOR_STATE_WIDTH)) goto cleanup;
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(share, sizeof(share));
    js_vbc4_wipe_volatile(artifact_commitment_share, sizeof(artifact_commitment_share));
    js_vbc4_wipe_volatile(reconstructed_artifact_commitment, sizeof(reconstructed_artifact_commitment));
    if (!ok && out_dek) js_vbc4_wipe_volatile(out_dek, JS_AKEN_EVALUATOR_STATE_WIDTH);
    return ok;
}

/*
 * AKEN v4 current-page envelope parser.
 *
 * This remains below the evaluator primitive and above the typed JNI stubs on
 * purpose: it is a locator-private binding parser only.  The typed JNI proof
 * remains a raw descriptor call-site proof.  An encoded page envelope is never
 * accepted from that JNI parameter and no function below opens a resource,
 * derives a key, or exposes a generic decoder.
 */
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_DESCRIPTOR_BINDING_DOMAIN "AKEN-v4-native-page-envelope-descriptor-v1"
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_CALL_SITE_BINDING_DOMAIN "AKEN-v4-native-page-envelope-call-site-v1"
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_ROUTE_BINDING_DOMAIN "AKEN-v4-native-page-envelope-route-v1"
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_BINDING_DOMAIN "AKEN-v4-native-page-envelope-v1"

typedef struct {
    const unsigned char *bytes;
    size_t length;
    size_t offset;
} js_aken_native_page_envelope_reader;

static int js_aken_native_page_envelope_constant_time_equal(
    const unsigned char *left,
    const unsigned char *right,
    size_t length
) {
    unsigned int difference = 0u;
    if (!left || !right) return 0;
    for (size_t index = 0u; index < length; index++) {
        difference |= (unsigned int)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static int js_aken_native_page_envelope_kind_is_valid(uint8_t resource_kind) {
    return resource_kind >= 1u && resource_kind <= 4u;
}

static int js_aken_native_page_request_is_valid(const js_aken_native_page_request *request) {
    if (!request || !js_aken_native_page_envelope_kind_is_valid(request->resource_kind) || request->page_index < 0) {
        return 0;
    }
    if (!request->encoded_handle || request->encoded_handle_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) {
        return 0;
    }
    if (!request->raw_call_site_proof || request->raw_call_site_proof_len == 0u ||
        request->raw_call_site_proof_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE) {
        return 0;
    }
    return 1;
}

static int js_aken_native_page_envelope_reader_read_bytes(
    js_aken_native_page_envelope_reader *reader,
    unsigned char *out,
    size_t length
) {
    if (!reader || !out || reader->offset > reader->length || length > reader->length - reader->offset) return 0;
    memcpy(out, reader->bytes + reader->offset, length);
    reader->offset += length;
    return 1;
}

static int js_aken_native_page_envelope_reader_read_ref(
    js_aken_native_page_envelope_reader *reader,
    const unsigned char **out,
    size_t length
) {
    if (!reader || !out || reader->offset > reader->length || length > reader->length - reader->offset) return 0;
    *out = reader->bytes + reader->offset;
    reader->offset += length;
    return 1;
}

static int js_aken_native_page_envelope_reader_read_u8(
    js_aken_native_page_envelope_reader *reader,
    uint8_t *out
) {
    const unsigned char *value = NULL;
    if (!out || !js_aken_native_page_envelope_reader_read_ref(reader, &value, 1u)) return 0;
    *out = value[0];
    return 1;
}

static int js_aken_native_page_envelope_reader_read_u32be(
    js_aken_native_page_envelope_reader *reader,
    uint32_t *out
) {
    const unsigned char *value = NULL;
    if (!out || !js_aken_native_page_envelope_reader_read_ref(reader, &value, 4u)) return 0;
    *out = ((uint32_t)value[0] << 24) |
        ((uint32_t)value[1] << 16) |
        ((uint32_t)value[2] << 8) |
        (uint32_t)value[3];
    return 1;
}

static int js_aken_native_page_envelope_reader_read_u64be(
    js_aken_native_page_envelope_reader *reader,
    uint64_t *out
) {
    const unsigned char *value = NULL;
    uint64_t decoded = 0u;
    if (!out || !js_aken_native_page_envelope_reader_read_ref(reader, &value, 8u)) return 0;
    for (size_t index = 0u; index < 8u; index++) {
        decoded = (decoded << 8) | (uint64_t)value[index];
    }
    *out = decoded;
    return 1;
}

static void js_aken_native_page_envelope_update_u32be(js_sha256_ctx *ctx, uint32_t value) {
    const unsigned char bytes[4] = {
        (unsigned char)(value >> 24),
        (unsigned char)(value >> 16),
        (unsigned char)(value >> 8),
        (unsigned char)value,
    };
    js_sha256_update(ctx, bytes, (int)sizeof(bytes));
}

static void js_aken_native_page_envelope_update_u64be(js_sha256_ctx *ctx, uint64_t value) {
    const unsigned char bytes[8] = {
        (unsigned char)(value >> 56),
        (unsigned char)(value >> 48),
        (unsigned char)(value >> 40),
        (unsigned char)(value >> 32),
        (unsigned char)(value >> 24),
        (unsigned char)(value >> 16),
        (unsigned char)(value >> 8),
        (unsigned char)value,
    };
    js_sha256_update(ctx, bytes, (int)sizeof(bytes));
}

static int js_aken_native_page_envelope_update_framed(
    js_sha256_ctx *ctx,
    const unsigned char *value,
    size_t value_len
) {
    if (!ctx || (value_len != 0u && !value) || value_len > (size_t)UINT32_MAX || value_len > (size_t)INT_MAX) {
        return 0;
    }
    js_aken_native_page_envelope_update_u32be(ctx, (uint32_t)value_len);
    if (value_len != 0u) js_sha256_update(ctx, value, (int)value_len);
    return 1;
}

static int js_aken_native_page_envelope_digest_one_framed(
    const unsigned char *domain,
    size_t domain_len,
    const unsigned char *value,
    size_t value_len,
    size_t maximum_value_len,
    unsigned char out_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx ctx;
    int ok = 0;
    if (!out_digest) return 0;
    js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    memset(&ctx, 0, sizeof(ctx));
    if (!domain || domain_len == 0u || domain_len > (size_t)INT_MAX || !value || value_len == 0u ||
        value_len > maximum_value_len) {
        goto cleanup;
    }
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, domain, (int)domain_len);
    if (!js_aken_native_page_envelope_update_framed(&ctx, value, value_len)) goto cleanup;
    js_sha256_final(&ctx, out_digest);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    if (!ok) js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    return ok;
}

static int js_aken_native_page_envelope_digest_route(
    const unsigned char *route_encoding,
    size_t route_encoding_len,
    const unsigned char locator_token[JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE],
    unsigned char out_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    static const unsigned char domain[] = JS_AKEN_NATIVE_PAGE_ENVELOPE_ROUTE_BINDING_DOMAIN;
    js_sha256_ctx ctx;
    int ok = 0;
    if (!out_digest) return 0;
    js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    memset(&ctx, 0, sizeof(ctx));
    if (!route_encoding || route_encoding_len == 0u || route_encoding_len > JS_AKEN_NATIVE_PAGE_ROUTE_MAX_SIZE ||
        !locator_token) {
        goto cleanup;
    }
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, domain, (int)(sizeof(domain) - 1u));
    if (!js_aken_native_page_envelope_update_framed(&ctx, route_encoding, route_encoding_len) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE)) {
        goto cleanup;
    }
    js_sha256_final(&ctx, out_digest);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    if (!ok) js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    return ok;
}

static int js_aken_native_page_envelope_record_is_well_formed(
    const js_aken_native_page_envelope *envelope,
    int require_successful_parse
) {
    if (!envelope || (require_successful_parse && envelope->parsed != 1u) ||
        !js_aken_native_page_envelope_kind_is_valid(envelope->resource_kind) || envelope->page_index < 0) {
        return 0;
    }
    if (envelope->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR) {
        return envelope->inline_descriptor && envelope->inline_descriptor_len != 0u &&
            envelope->inline_descriptor_len <= JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_INLINE_DESCRIPTOR_SIZE;
    }
    if (envelope->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_COMPACT_LOCATOR) {
        return !envelope->inline_descriptor && envelope->inline_descriptor_len == 0u;
    }
    return 0;
}

static int js_aken_native_page_resolved_descriptor_is_well_formed(
    const js_aken_native_page_resolved_descriptor *resolved
) {
    if (!resolved || !js_aken_native_page_envelope_kind_is_valid(resolved->resource_kind) ||
        resolved->page_index < 0) {
        return 0;
    }
    if (!resolved->encoded_handle ||
        resolved->encoded_handle_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE ||
        !resolved->locator_token ||
        resolved->locator_token_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE ||
        !resolved->evaluator_fingerprint ||
        resolved->evaluator_fingerprint_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE ||
        !resolved->artifact_commitment ||
        resolved->artifact_commitment_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE ||
        !resolved->descriptor_encoding || resolved->descriptor_encoding_len == 0u ||
        resolved->descriptor_encoding_len > JS_AKEN_NATIVE_PAGE_DESCRIPTOR_MAX_SIZE ||
        !resolved->route_encoding || resolved->route_encoding_len == 0u ||
        resolved->route_encoding_len > JS_AKEN_NATIVE_PAGE_ROUTE_MAX_SIZE) {
        return 0;
    }
    return 1;
}

static int js_aken_native_page_envelope_digest_envelope(
    const js_aken_native_page_envelope *envelope,
    unsigned char out_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    static const unsigned char domain[] = JS_AKEN_NATIVE_PAGE_ENVELOPE_BINDING_DOMAIN;
    js_sha256_ctx ctx;
    int ok = 0;
    if (!out_digest) return 0;
    js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    memset(&ctx, 0, sizeof(ctx));
    if (!js_aken_native_page_envelope_record_is_well_formed(envelope, 0)) goto cleanup;
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, domain, (int)(sizeof(domain) - 1u));
    js_sha256_update(&ctx, &envelope->form, 1);
    js_aken_native_page_envelope_update_u64be(&ctx, envelope->entry_token);
    js_sha256_update(&ctx, &envelope->resource_kind, 1);
    js_aken_native_page_envelope_update_u32be(&ctx, (uint32_t)envelope->page_index);
    if (!js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->descriptor_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->call_site_proof_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->route_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    if (envelope->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR &&
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            envelope->inline_descriptor,
            envelope->inline_descriptor_len)) {
        goto cleanup;
    }
    js_sha256_final(&ctx, out_digest);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    if (!ok) js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    return ok;
}

JS_HIDDEN void js_aken_native_page_envelope_wipe(js_aken_native_page_envelope *envelope) {
    if (!envelope) return;
    js_vbc4_wipe_volatile(envelope, sizeof(*envelope));
}

JS_HIDDEN int js_aken_native_page_envelope_parse(
    const unsigned char *encoded_envelope,
    size_t encoded_envelope_len,
    const js_aken_native_page_request *request,
    js_aken_native_page_envelope *out_envelope
) {
    static const unsigned char descriptor_domain[] = JS_AKEN_NATIVE_PAGE_ENVELOPE_DESCRIPTOR_BINDING_DOMAIN;
    static const unsigned char call_site_domain[] = JS_AKEN_NATIVE_PAGE_ENVELOPE_CALL_SITE_BINDING_DOMAIN;
    js_aken_native_page_envelope_reader reader;
    unsigned char received_envelope_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char expected_envelope_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char expected_call_site_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char expected_descriptor_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    uint32_t page_index = 0u;
    uint32_t inline_descriptor_len = 0u;
    int ok = 0;
    if (!out_envelope) goto cleanup;
    js_aken_native_page_envelope_wipe(out_envelope);
    if (!encoded_envelope || encoded_envelope_len < JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE ||
        encoded_envelope_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE || !js_aken_native_page_request_is_valid(request)) {
        goto cleanup;
    }
    reader.bytes = encoded_envelope;
    reader.length = encoded_envelope_len;
    reader.offset = 0u;
    if (!js_aken_native_page_envelope_reader_read_u8(&reader, &out_envelope->parsed) ||
        out_envelope->parsed != JS_AKEN_NATIVE_PAGE_ENVELOPE_VERSION ||
        !js_aken_native_page_envelope_reader_read_u8(&reader, &out_envelope->form) ||
        (out_envelope->form != JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR &&
            out_envelope->form != JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_COMPACT_LOCATOR) ||
        !js_aken_native_page_envelope_reader_read_u64be(&reader, &out_envelope->entry_token) ||
        !js_aken_native_page_envelope_reader_read_u8(&reader, &out_envelope->resource_kind) ||
        !js_aken_native_page_envelope_kind_is_valid(out_envelope->resource_kind) ||
        !js_aken_native_page_envelope_reader_read_u32be(&reader, &page_index) ||
        page_index > (uint32_t)INT_MAX) {
        goto cleanup;
    }
    out_envelope->page_index = (jint)page_index;
    if (!js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->descriptor_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->call_site_proof_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            out_envelope->route_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    if (out_envelope->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR) {
        if (!js_aken_native_page_envelope_reader_read_u32be(&reader, &inline_descriptor_len) ||
            inline_descriptor_len == 0u ||
            inline_descriptor_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_INLINE_DESCRIPTOR_SIZE ||
            !js_aken_native_page_envelope_reader_read_ref(
                &reader,
                &out_envelope->inline_descriptor,
                (size_t)inline_descriptor_len)) {
            goto cleanup;
        }
        out_envelope->inline_descriptor_len = (size_t)inline_descriptor_len;
    }
    if (!js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            received_envelope_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        reader.offset != reader.length ||
        !js_aken_native_page_envelope_record_is_well_formed(out_envelope, 0)) {
        goto cleanup;
    }

    /* The encoded envelope and raw JNI proof are independently transported. */
    if (out_envelope->entry_token != request->entry_token ||
        out_envelope->resource_kind != request->resource_kind ||
        out_envelope->page_index != request->page_index ||
        !js_aken_native_page_envelope_constant_time_equal(
            out_envelope->encoded_handle,
            request->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE)) {
        goto cleanup;
    }
    if (!js_aken_native_page_envelope_digest_one_framed(
            call_site_domain,
            sizeof(call_site_domain) - 1u,
            request->raw_call_site_proof,
            request->raw_call_site_proof_len,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE,
            expected_call_site_binding) ||
        !js_aken_native_page_envelope_constant_time_equal(
            out_envelope->call_site_proof_binding,
            expected_call_site_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    if (out_envelope->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR &&
        (!js_aken_native_page_envelope_digest_one_framed(
            descriptor_domain,
            sizeof(descriptor_domain) - 1u,
            out_envelope->inline_descriptor,
            out_envelope->inline_descriptor_len,
            JS_AKEN_NATIVE_PAGE_DESCRIPTOR_MAX_SIZE,
            expected_descriptor_binding) ||
        !js_aken_native_page_envelope_constant_time_equal(
            out_envelope->descriptor_binding,
            expected_descriptor_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE))) {
        goto cleanup;
    }
    if (!js_aken_native_page_envelope_digest_envelope(out_envelope, expected_envelope_binding) ||
        !js_aken_native_page_envelope_constant_time_equal(
            received_envelope_binding,
            expected_envelope_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    out_envelope->parsed = 1u;
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(received_envelope_binding, sizeof(received_envelope_binding));
    js_vbc4_wipe_volatile(expected_envelope_binding, sizeof(expected_envelope_binding));
    js_vbc4_wipe_volatile(expected_call_site_binding, sizeof(expected_call_site_binding));
    js_vbc4_wipe_volatile(expected_descriptor_binding, sizeof(expected_descriptor_binding));
    js_vbc4_wipe_volatile(&reader, sizeof(reader));
    if (!ok && out_envelope) js_aken_native_page_envelope_wipe(out_envelope);
    return ok;
}

JS_HIDDEN int js_aken_native_page_envelope_verify_resolved_bindings(
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved
) {
    static const unsigned char descriptor_domain[] = JS_AKEN_NATIVE_PAGE_ENVELOPE_DESCRIPTOR_BINDING_DOMAIN;
    unsigned char expected_descriptor_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char expected_route_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    int inline_matches = 0;
    int identity_matches = 0;
    int ok = 0;
    if (!js_aken_native_page_envelope_record_is_well_formed(envelope, 1) ||
        !js_aken_native_page_resolved_descriptor_is_well_formed(resolved)) {
        goto cleanup;
    }
    if (!js_aken_native_page_envelope_digest_one_framed(
            descriptor_domain,
            sizeof(descriptor_domain) - 1u,
            resolved->descriptor_encoding,
            resolved->descriptor_encoding_len,
            JS_AKEN_NATIVE_PAGE_DESCRIPTOR_MAX_SIZE,
            expected_descriptor_binding) ||
        !js_aken_native_page_envelope_digest_route(
            resolved->route_encoding,
            resolved->route_encoding_len,
            envelope->locator_token,
            expected_route_binding)) {
        goto cleanup;
    }
    identity_matches = envelope->resource_kind == resolved->resource_kind &&
        envelope->page_index == resolved->page_index &&
        js_aken_native_page_envelope_constant_time_equal(
            envelope->encoded_handle,
            resolved->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            envelope->locator_token,
            resolved->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            envelope->evaluator_fingerprint,
            resolved->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            envelope->artifact_commitment,
            resolved->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    inline_matches = envelope->form != JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR ||
        (envelope->inline_descriptor_len == resolved->descriptor_encoding_len &&
            js_aken_native_page_envelope_constant_time_equal(
                envelope->inline_descriptor,
                resolved->descriptor_encoding,
                resolved->descriptor_encoding_len));
    if (!identity_matches || !inline_matches ||
        !js_aken_native_page_envelope_constant_time_equal(
            envelope->descriptor_binding,
            expected_descriptor_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            envelope->route_binding,
            expected_route_binding,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(expected_descriptor_binding, sizeof(expected_descriptor_binding));
    js_vbc4_wipe_volatile(expected_route_binding, sizeof(expected_route_binding));
    return ok;
}

static jobject JNICALL jsw_a0(JNIEnv *env, jclass cls, jlong entry_token, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof, jobjectArray args) {
    (void)cls; (void)entry_token; (void)args;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_a0, 0)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    if (js_aken_bridge_request_is_valid(env, encoded_handle, page_index, call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN VM page route is unavailable");
    }
    (void)js_protected_runtime_leave(env);
    return NULL;
}

static jbyteArray JNICALL jsw_a1(JNIEnv *env, jclass cls, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof) {
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_a1, 0)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    if (js_aken_bridge_request_is_valid(env, encoded_handle, page_index, call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN string page route is unavailable");
    }
    (void)js_protected_runtime_leave(env);
    return NULL;
}

static jbyteArray JNICALL jsw_a2(JNIEnv *env, jclass cls, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof) {
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_a2, 0)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    if (js_aken_bridge_request_is_valid(env, encoded_handle, page_index, call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN class page route is unavailable");
    }
    (void)js_protected_runtime_leave(env);
    return NULL;
}

static jbyteArray JNICALL jsw_a3(JNIEnv *env, jclass cls, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof) {
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_a3, 0)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    if (js_aken_bridge_request_is_valid(env, encoded_handle, page_index, call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN native chunk route is unavailable");
    }
    (void)js_protected_runtime_leave(env);
    return NULL;
}

static void js_protected_runtime_failure(JNIEnv *env) {
    if (!env || (*env)->ExceptionCheck(env)) return;
    jclass failure = (*env)->FindClass(env, "java/lang/SecurityException");
    if (!failure || (*env)->ExceptionCheck(env)) return;
    (*env)->ThrowNew(env, failure, "native protected section lifecycle failure");
    (*env)->DeleteLocalRef(env, failure);
}

static int js_protected_runtime_enter(JNIEnv *env) {
    if (js_protected_section_enter()) return 1;
    js_protected_runtime_failure(env);
    return 0;
}

static int js_protected_runtime_leave(JNIEnv *env) {
    if (js_protected_section_leave()) return 1;
    js_protected_runtime_failure(env);
    return 0;
}

static jint JNICALL jsw_k0(JNIEnv *env, jclass cls, jstring platform) {
    if (!js_protected_runtime_enter(env)) return JNI_ERR;
    jint result = jsn_k0(env, cls, platform);
    return js_protected_runtime_leave(env) ? result : JNI_ERR;
}

static jint JNICALL jsw_k1(JNIEnv *env, jclass cls, jbyteArray data, jbyteArray expected_mac) {
    if (!js_protected_runtime_enter(env)) return JNI_ERR;
    jint result = jsn_k1(env, cls, data, expected_mac);
    return js_protected_runtime_leave(env) ? result : JNI_ERR;
}

static jint JNICALL jsw_k3(JNIEnv *env, jclass cls) {
    if (!js_protected_runtime_enter(env)) return JNI_ERR;
    jint result = jsn_k3(env, cls);
    return js_protected_runtime_leave(env) ? result : JNI_ERR;
}

static jbyteArray JNICALL jsw_k4(JNIEnv *env, jclass cls, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jbyteArray result = jsn_k4(env, cls, encrypted, keyArr, ivArr);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jstring JNICALL jsw_k5(JNIEnv *env, jclass cls) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_k5(env, cls);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jlong JNICALL jsw_k6(JNIEnv *env, jclass cls) {
    if (!js_protected_runtime_enter(env)) return 0;
    jlong result = jsn_k6(env, cls);
    return js_protected_runtime_leave(env) ? result : 0;
}

static jboolean JNICALL jsw_k7(JNIEnv *env, jclass cls, jbyteArray material) {
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_k7, 1)) return JNI_FALSE;
    if (!js_protected_runtime_enter(env)) return JNI_FALSE;
    jboolean result = jsn_k7(env, cls, material);
    return js_protected_runtime_leave(env) ? result : JNI_FALSE;
}

static jboolean JNICALL jsw_k11(JNIEnv *env, jclass cls) {
    if (!js_protected_runtime_enter(env)) return JNI_FALSE;
    jboolean result = jsn_k11(env, cls);
    return js_protected_runtime_leave(env) ? result : JNI_FALSE;
}

static void JNICALL jsw_k12(JNIEnv *env, jclass cls) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_k12(env, cls);
    (void)js_protected_runtime_leave(env);
}

static void JNICALL jsw_k9(JNIEnv *env, jclass cls, jbyteArray preload_index, jbyteArray commitments, jbyteArray startup_nonce) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_k9(env, cls, preload_index, commitments, startup_nonce);
    (void)js_protected_runtime_leave(env);
}

static jbyteArray JNICALL jsw_k10(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length) {
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_k10, 1)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    jbyteArray result = jsn_k10(env, cls, keyIdArr, saltArr, length);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jbyteArray JNICALL jsw_k14(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jbyteArray nonceArr, jbyteArray ciphertextArr, jbyteArray aadArr, jint keyLength) {
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_k14, 1)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    jbyteArray result = jsn_k14(env, cls, keyIdArr, saltArr, nonceArr, ciphertextArr, aadArr, keyLength);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jstring JNICALL jsw_k15(JNIEnv *env, jclass cls, jbyteArray valueArr) {
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_k15, 1)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_k15(env, cls, valueArr);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jbyteArray JNICALL jsw_k13(JNIEnv *env, jclass cls, jbyteArray encoded) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jbyteArray result = jsn_k13(env, cls, encoded);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static void JNICALL jsw_r0(JNIEnv *env, jclass cls, jstring a, jstring b) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r0(env, cls, a, b);
    (void)js_protected_runtime_leave(env);
}

static void JNICALL jsw_r1(JNIEnv *env, jclass cls, jstring a, jstring b) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r1(env, cls, a, b);
    (void)js_protected_runtime_leave(env);
}

static void JNICALL jsw_r2(JNIEnv *env, jclass cls, jstring value) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r2(env, cls, value);
    (void)js_protected_runtime_leave(env);
}

static void JNICALL jsw_r3(JNIEnv *env, jclass cls, jstring value) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r3(env, cls, value);
    (void)js_protected_runtime_leave(env);
}

static void JNICALL jsw_r4(JNIEnv *env, jclass cls, jstring value, jclass ownerClass) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r4(env, cls, value, ownerClass);
    (void)js_protected_runtime_leave(env);
}

static jstring JNICALL jsw_r11(JNIEnv *env, jclass cls, jbyteArray value) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_r11(env, cls, value);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jstring JNICALL jsw_r12(JNIEnv *env, jclass cls, jstring value) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_r12(env, cls, value);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jstring JNICALL jsw_r13(JNIEnv *env, jclass cls, jstring value) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_r13(env, cls, value);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jstring JNICALL jsw_r16(JNIEnv *env, jclass cls, jstring bindingSource, jstring salt, jstring expectedFingerprint) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_r16(env, cls, bindingSource, salt, expectedFingerprint);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static void JNICALL jsw_r17(JNIEnv *env, jclass cls, jstring expectedToken, jstring bindingSource, jstring salt, jstring expectedFingerprint) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r17(env, cls, expectedToken, bindingSource, salt, expectedFingerprint);
    (void)js_protected_runtime_leave(env);
}

static jstring JNICALL jsw_r18(JNIEnv *env, jclass cls) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jstring result = jsn_r18(env, cls);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jobject JNICALL jsw_r20(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jobject result = jsn_r20(env, cls, entryToken, resourcePath, args);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jbyteArray JNICALL jsw_r21(JNIEnv *env, jclass cls, jbyteArray payload, jint seed, jint flags, jlong classIdentityHigh, jlong classIdentityLow) {
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_r21, 1)) return NULL;
    if (!js_protected_runtime_enter(env)) return NULL;
    jbyteArray result = jsn_r21(env, cls, payload, seed, flags, classIdentityHigh, classIdentityLow);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static jobject JNICALL jsw_r22(JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args) {
    if (!js_protected_runtime_enter(env)) return NULL;
    jobject result = jsn_r22(env, cls, entryToken, args);
    return js_protected_runtime_leave(env) ? result : NULL;
}

static void JNICALL jsw_r23(JNIEnv *env, jclass cls, jlong entryToken) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r23(env, cls, entryToken);
    (void)js_protected_runtime_leave(env);
}

static void JNICALL jsw_r24(JNIEnv *env, jclass cls, jlong entryToken, jint arg0) {
    if (!js_protected_runtime_enter(env)) return;
    jsn_r24(env, cls, entryToken, arg0);
    (void)js_protected_runtime_leave(env);
}

static jint JNICALL jsw_r25(JNIEnv *env, jclass cls, jlong entryToken) {
    if (!js_protected_runtime_enter(env)) return 0;
    jint result = jsn_r25(env, cls, entryToken);
    return js_protected_runtime_leave(env) ? result : 0;
}

static jint JNICALL jsw_r26(JNIEnv *env, jclass cls, jlong entryToken, jint arg0) {
    if (!js_protected_runtime_enter(env)) return 0;
    jint result = jsn_r26(env, cls, entryToken, arg0);
    return js_protected_runtime_leave(env) ? result : 0;
}

static const js_native_abi_table js_native_abi_table_instance = {
    JS_NATIVE_ABI_TABLE_VERSION,
    jsw_k0,
    jsw_k1,
    jsw_k3,
    jsw_k4,
    jsw_k5,
    jsw_k6,
    jsw_k7,
    jsw_k11,
    jsw_k12,
    jsw_k9,
    jsw_k10,
    jsw_k14,
    jsw_k15,
    jsw_k13,
    jsw_r20,
    jsw_r22,
    jsw_r23,
    jsw_r25,
    jsw_r26,
    jsw_r24,
    jsw_a0,
    jsw_a1,
    jsw_a2,
    jsw_a3,
};

JS_EXPORT const js_native_abi_table *js_native_abi_table_v1(void) {
    return &js_native_abi_table_instance;
}

static jclass js_jni_cache_global_class(JNIEnv *env, const char *name) {
    jclass local = (*env)->FindClass(env, name);
    if ((*env)->ExceptionCheck(env) || !local) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    jclass global = (jclass)(*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if ((*env)->ExceptionCheck(env) || !global) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    return global;
}

static int js_jni_cache_require_member(JNIEnv *env, const void *member) {
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return member != NULL;
}

JS_HIDDEN void js_jni_cache_destroy(JNIEnv *env) {
    if (!env) {
        memset(&js_jni_cache, 0, sizeof(js_jni_cache));
        return;
    }
#define JS_JNI_DELETE_GLOBAL(field) do { if (js_jni_cache.field) (*env)->DeleteGlobalRef(env, js_jni_cache.field); } while (0)
    JS_JNI_DELETE_GLOBAL(object_class);
    JS_JNI_DELETE_GLOBAL(string_class);
    JS_JNI_DELETE_GLOBAL(class_loader_class);
    JS_JNI_DELETE_GLOBAL(byte_array_class);
    JS_JNI_DELETE_GLOBAL(class_class);
    JS_JNI_DELETE_GLOBAL(thread_class);
    JS_JNI_DELETE_GLOBAL(input_stream_class);
    JS_JNI_DELETE_GLOBAL(string_builder_class);
    JS_JNI_DELETE_GLOBAL(runtime_exception_class);
    JS_JNI_DELETE_GLOBAL(security_exception_class);
    JS_JNI_DELETE_GLOBAL(throwable_class);
    JS_JNI_DELETE_GLOBAL(stack_trace_element_class);
    JS_JNI_DELETE_GLOBAL(reflect_array_class);
    JS_JNI_DELETE_GLOBAL(system_class);
    JS_JNI_DELETE_GLOBAL(integer_class);
    JS_JNI_DELETE_GLOBAL(boolean_class);
    JS_JNI_DELETE_GLOBAL(byte_class);
    JS_JNI_DELETE_GLOBAL(short_class);
    JS_JNI_DELETE_GLOBAL(character_class);
    JS_JNI_DELETE_GLOBAL(long_class);
    JS_JNI_DELETE_GLOBAL(float_class);
    JS_JNI_DELETE_GLOBAL(double_class);
    JS_JNI_DELETE_GLOBAL(void_class);
#undef JS_JNI_DELETE_GLOBAL
    memset(&js_jni_cache, 0, sizeof(js_jni_cache));
}

JS_HIDDEN int js_jni_cache_init(JNIEnv *env) {
    if (!env) return 0;
    memset(&js_jni_cache, 0, sizeof(js_jni_cache));
#define JS_JNI_CLASS(field, name) do { js_jni_cache.field = js_jni_cache_global_class(env, name); if (!js_jni_cache.field) goto fail; } while (0)
#define JS_JNI_METHOD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetMethodID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)
#define JS_JNI_STATIC_METHOD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetStaticMethodID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)
#define JS_JNI_FIELD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetFieldID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)
#define JS_JNI_STATIC_FIELD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetStaticFieldID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)

    JS_JNI_CLASS(object_class, "java/lang/Object");
    JS_JNI_CLASS(string_class, "java/lang/String");
    JS_JNI_CLASS(class_loader_class, "java/lang/ClassLoader");
    JS_JNI_CLASS(byte_array_class, "[B");
    JS_JNI_CLASS(class_class, "java/lang/Class");
    JS_JNI_CLASS(thread_class, "java/lang/Thread");
    JS_JNI_CLASS(input_stream_class, "java/io/InputStream");
    JS_JNI_CLASS(string_builder_class, "java/lang/StringBuilder");
    JS_JNI_CLASS(runtime_exception_class, "java/lang/RuntimeException");
    JS_JNI_CLASS(security_exception_class, "java/lang/SecurityException");
    JS_JNI_CLASS(throwable_class, "java/lang/Throwable");
    JS_JNI_CLASS(reflect_array_class, "java/lang/reflect/Array");
    JS_JNI_CLASS(system_class, "java/lang/System");
    JS_JNI_CLASS(integer_class, "java/lang/Integer");
    JS_JNI_CLASS(boolean_class, "java/lang/Boolean");
    JS_JNI_CLASS(byte_class, "java/lang/Byte");
    JS_JNI_CLASS(short_class, "java/lang/Short");
    JS_JNI_CLASS(character_class, "java/lang/Character");
    JS_JNI_CLASS(long_class, "java/lang/Long");
    JS_JNI_CLASS(float_class, "java/lang/Float");
    JS_JNI_CLASS(double_class, "java/lang/Double");
    JS_JNI_CLASS(void_class, "java/lang/Void");

    JS_JNI_METHOD(class_loader_get_resource_as_stream, class_loader_class, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    JS_JNI_METHOD(class_loader_load_class, class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    JS_JNI_METHOD(class_loader_define_class, class_loader_class, "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;");
    JS_JNI_METHOD(class_loader_define_class_pd, class_loader_class, "defineClass", "(Ljava/lang/String;[BIILjava/security/ProtectionDomain;)Ljava/lang/Class;");
    JS_JNI_METHOD(class_get_class_loader, class_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
    JS_JNI_METHOD(class_get_name, class_class, "getName", "()Ljava/lang/String;");
    JS_JNI_METHOD(class_get_resource_as_stream, class_class, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    JS_JNI_METHOD(class_is_array, class_class, "isArray", "()Z");
    JS_JNI_METHOD(class_get_component_type, class_class, "getComponentType", "()Ljava/lang/Class;");
    JS_JNI_STATIC_METHOD(thread_current_thread, thread_class, "currentThread", "()Ljava/lang/Thread;");
    JS_JNI_METHOD(thread_get_context_class_loader, thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    /* readAllBytes is Java 9+; keep the runtime loadable on Java 8 by treating it as optional. */
    js_jni_cache.input_stream_read_all_bytes = (*env)->GetMethodID(env, js_jni_cache.input_stream_class, "readAllBytes", "()[B");
    if ((*env)->ExceptionCheck(env) || !js_jni_cache.input_stream_read_all_bytes) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        js_jni_cache.input_stream_read_all_bytes = NULL;
    }
    JS_JNI_METHOD(input_stream_close, input_stream_class, "close", "()V");
    JS_JNI_METHOD(string_builder_init, string_builder_class, "<init>", "()V");
    JS_JNI_METHOD(string_builder_append_string, string_builder_class, "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
    JS_JNI_METHOD(string_builder_to_string, string_builder_class, "toString", "()Ljava/lang/String;");
    JS_JNI_METHOD(runtime_exception_init, runtime_exception_class, "<init>", "(Ljava/lang/String;)V");
    {
        jclass local_stack_trace_element = (*env)->FindClass(env, "java/lang/StackTraceElement");
        if ((*env)->ExceptionCheck(env) || !local_stack_trace_element) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        } else {
            js_jni_cache.stack_trace_element_class = (jclass)(*env)->NewGlobalRef(env, local_stack_trace_element);
            (*env)->DeleteLocalRef(env, local_stack_trace_element);
            if ((*env)->ExceptionCheck(env) || !js_jni_cache.stack_trace_element_class) {
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                js_jni_cache.stack_trace_element_class = NULL;
            } else {
                js_jni_cache.throwable_set_stack_trace = (*env)->GetMethodID(env, js_jni_cache.throwable_class, "setStackTrace", "([Ljava/lang/StackTraceElement;)V");
                if ((*env)->ExceptionCheck(env) || !js_jni_cache.throwable_set_stack_trace) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); js_jni_cache.throwable_set_stack_trace = NULL; }
                js_jni_cache.stack_trace_element_init = (*env)->GetMethodID(env, js_jni_cache.stack_trace_element_class, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");
                if ((*env)->ExceptionCheck(env) || !js_jni_cache.stack_trace_element_init) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); js_jni_cache.stack_trace_element_init = NULL; }
            }
        }
    }
    JS_JNI_METHOD(integer_int_value, integer_class, "intValue", "()I");
    JS_JNI_METHOD(boolean_boolean_value, boolean_class, "booleanValue", "()Z");
    JS_JNI_METHOD(byte_byte_value, byte_class, "byteValue", "()B");
    JS_JNI_METHOD(short_short_value, short_class, "shortValue", "()S");
    JS_JNI_METHOD(character_char_value, character_class, "charValue", "()C");
    JS_JNI_METHOD(long_long_value, long_class, "longValue", "()J");
    JS_JNI_METHOD(float_float_value, float_class, "floatValue", "()F");
    JS_JNI_METHOD(double_double_value, double_class, "doubleValue", "()D");
    JS_JNI_STATIC_METHOD(integer_value_of, integer_class, "valueOf", "(I)Ljava/lang/Integer;");
    JS_JNI_STATIC_METHOD(boolean_value_of, boolean_class, "valueOf", "(Z)Ljava/lang/Boolean;");
    JS_JNI_STATIC_METHOD(byte_value_of, byte_class, "valueOf", "(B)Ljava/lang/Byte;");
    JS_JNI_STATIC_METHOD(short_value_of, short_class, "valueOf", "(S)Ljava/lang/Short;");
    JS_JNI_STATIC_METHOD(character_value_of, character_class, "valueOf", "(C)Ljava/lang/Character;");
    JS_JNI_STATIC_METHOD(long_value_of, long_class, "valueOf", "(J)Ljava/lang/Long;");
    JS_JNI_STATIC_METHOD(float_value_of, float_class, "valueOf", "(F)Ljava/lang/Float;");
    JS_JNI_STATIC_METHOD(double_value_of, double_class, "valueOf", "(D)Ljava/lang/Double;");
    JS_JNI_STATIC_METHOD(string_value_of_object, string_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_int, string_class, "valueOf", "(I)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_long, string_class, "valueOf", "(J)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_float, string_class, "valueOf", "(F)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_double, string_class, "valueOf", "(D)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_boolean, string_class, "valueOf", "(Z)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_char, string_class, "valueOf", "(C)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(reflect_array_new_instance_dims, reflect_array_class, "newInstance", "(Ljava/lang/Class;[I)Ljava/lang/Object;");
    JS_JNI_STATIC_METHOD(reflect_array_new_instance_len, reflect_array_class, "newInstance", "(Ljava/lang/Class;I)Ljava/lang/Object;");
    JS_JNI_STATIC_METHOD(system_arraycopy, system_class, "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V");
    JS_JNI_STATIC_FIELD(integer_type_field, integer_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(boolean_type_field, boolean_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(byte_type_field, byte_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(short_type_field, short_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(character_type_field, character_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(long_type_field, long_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(float_type_field, float_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(double_type_field, double_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(void_type_field, void_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_FIELD(integer_value_field, integer_class, "value", "I");
    JS_JNI_FIELD(boolean_value_field, boolean_class, "value", "Z");
    JS_JNI_FIELD(byte_value_field, byte_class, "value", "B");
    JS_JNI_FIELD(short_value_field, short_class, "value", "S");
    JS_JNI_FIELD(character_value_field, character_class, "value", "C");
    JS_JNI_FIELD(long_value_field, long_class, "value", "J");
    JS_JNI_FIELD(float_value_field, float_class, "value", "F");
    JS_JNI_FIELD(double_value_field, double_class, "value", "D");

    js_jni_cache.initialized = 1;
#undef JS_JNI_CLASS
#undef JS_JNI_METHOD
#undef JS_JNI_STATIC_METHOD
#undef JS_JNI_FIELD
#undef JS_JNI_STATIC_FIELD
    return 1;
fail:
#undef JS_JNI_CLASS
#undef JS_JNI_METHOD
#undef JS_JNI_STATIC_METHOD
#undef JS_JNI_FIELD
#undef JS_JNI_STATIC_FIELD
    js_jni_cache_destroy(env);
    return 0;
}

static int js_register_natives(JNIEnv *env, const char *class_name, const JNINativeMethod *methods, int count, int required) {
    jclass cls = required ? js_vm_find_registration_class(env, class_name) : (*env)->FindClass(env, class_name);
    if (!cls) {
        js_vm_clear_exception(env);
        return required ? 0 : 1;
    }
    if ((*env)->RegisterNatives(env, cls, methods, count) != 0) {
        js_vm_clear_exception(env);
        return required ? 0 : 1;
    }
    if ((*env)->ExceptionCheck(env)) {
        js_vm_clear_exception(env);
        return required ? 0 : 1;
    }
    return 1;
}

static int js_register_bound_natives(JNIEnv *env, const char *class_name, const JNINativeMethod *methods, int count, int required) {
    char *mapped = js_lookup_bound_class(env, class_name);
    const char *effective_name = mapped && mapped[0] ? mapped : class_name;
    JNINativeMethod *effective_methods = NULL;
    char **owned_method_names = NULL;
    const JNINativeMethod *methods_to_register = methods;
    if (count > 0) {
        effective_methods = (JNINativeMethod*)calloc((size_t)count, sizeof(JNINativeMethod));
        owned_method_names = (char**)calloc((size_t)count, sizeof(char*));
        if (effective_methods && owned_method_names) {
            for (int i = 0; i < count; i++) {
                effective_methods[i] = methods[i];
                char *method_name = js_lookup_bound_method(env, class_name, methods[i].name, methods[i].signature);
                if (method_name && method_name[0]) {
                    effective_methods[i].name = method_name;
                    owned_method_names[i] = method_name;
                } else {
                    free(method_name);
                }
            }
            methods_to_register = effective_methods;
        }
    }
    int ok = js_register_natives(env, effective_name, methods_to_register, count, required);
    if (owned_method_names) {
        for (int i = 0; i < count; i++) free(owned_method_names[i]);
    }
    free(owned_method_names);
    free(effective_methods);
    free(mapped);
    return ok;
}

static int js_register_native_group(JNIEnv *env, char *owner, JNINativeMethod *methods, int count, int required) {
    int ready = owner != NULL;
    for (int i = 0; ready && i < count; i++) {
        if (!methods[i].name) ready = 0;
    }
    int ok = ready ? js_register_bound_natives(env, owner, methods, count, required) : (required ? 0 : 1);
    for (int i = 0; i < count; i++) free((void*)methods[i].name);
    free(owner);
    return ok;
}

static int js_register_optional_natives(JNIEnv *env) {
    JNINativeMethod anti_instrumentation_methods[] = {{js_native_name("Check", "Instr", "umentation"), "(Ljava/lang/String;Ljava/lang/String;)V", (void*)jsw_r0}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiInstr", "umentation", "Helper"), anti_instrumentation_methods, 1, 0)) return 0;

    JNINativeMethod anti_jvmti_methods[] = {{js_native_name("Check", "JvmTi", "Agents"), "(Ljava/lang/String;Ljava/lang/String;)V", (void*)jsw_r1}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiJvm", "Ti", "Helper"), anti_jvmti_methods, 1, 0)) return 0;

    JNINativeMethod anti_bytebuddy_methods[] = {{js_native_name("Check", "Byte", "Buddy"), "(Ljava/lang/String;)V", (void*)jsw_r2}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiByte", "Buddy", "Helper"), anti_bytebuddy_methods, 1, 0)) return 0;

    JNINativeMethod anti_dump_runtime_methods[] = {
        {js_native_name("Init", "ialize", "Protection"), "(Ljava/lang/String;)V", (void*)jsw_r3},
        {js_native_name("Init", "ialize", "Protection"), "(Ljava/lang/String;Ljava/lang/Class;)V", (void*)jsw_r4},
    };
    if (!js_register_native_group(env, js_helper_owner("An", "tiDump", "Runtime", "Helper"), anti_dump_runtime_methods, 2, 0)) return 0;

    JNINativeMethod anti_dump_methods[] = {
        {js_native_name("Build", "String", ""), "([B)Ljava/lang/String;", (void*)jsw_r11},
        {js_native_name("Build", "StringFrom", "B64"), "(Ljava/lang/String;)Ljava/lang/String;", (void*)jsw_r12},
        {js_native_name("Decode", "String", ""), "(Ljava/lang/String;)Ljava/lang/String;", (void*)jsw_r13},
    };
    if (!js_register_native_group(env, js_helper_owner("An", "tiDump", "", "Helper"), anti_dump_methods, 3, 0)) return 0;

    JNINativeMethod string_encryption_methods[] = {{js_native_name("Decode", "String", ""), "([BIIJJ)[B", (void*)jsw_r21}};
    if (!js_register_native_group(env, js_helper_owner("String", "Encryption", "", "Helper"), string_encryption_methods, 1, 0)) return 0;

    JNINativeMethod environment_methods[] = {
        {js_native_name("Derive", "Key", ""), "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)jsw_r16},
        {js_native_name("Verify", "Environment", ""), "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", (void*)jsw_r17},
        {js_native_name("Get", "Machine", "Fingerprint"), "()Ljava/lang/String;", (void*)jsw_r18},
    };
    if (!js_register_native_group(env, js_helper_owner("Environment", "Binding", "", "Helper"), environment_methods, 3, 0)) return 0;
    return 1;
}

JS_HIDDEN int js_jni_register_deferred_natives(JNIEnv *env) {
    if (!env || !js_jni_cache.initialized) return 0;
    return js_register_optional_natives(env);
}

static int js_register_all_natives(JNIEnv *env) {
    JNINativeMethod jni_microkernel_methods[] = {
        {js_native_name("In", "it", ""), "(Ljava/lang/String;)I", (void*)jsw_k0},
        {js_native_name("Ver", "ify", ""), "([B[B)I", (void*)jsw_k1},
        {js_native_name("Heart", "beat", ""), "()I", (void*)jsw_k3},
        {js_native_name("Get", "Ver", "sion"), "()Ljava/lang/String;", (void*)jsw_k5},
        {js_native_name("Get", "Boot", "Token"), "()J", (void*)jsw_k6},
        {js_native_name("Install", "Boot", "Material"), "([B)Z", (void*)jsw_k7},
        {js_native_name("Is", "BootMaterial", "Ready"), "()Z", (void*)jsw_k11},
        {js_native_name("Abort", "Boot", "Material"), "()V", (void*)jsw_k12},
        {js_native_name("Preload", "Runtime", "Resources"), "([B[B[B)V", (void*)jsw_k9},
        {js_native_name("De", "crypt", "Aes"), "([B[B[B)[B", (void*)jsw_k4},
        {js_native_name("Derive", "ClassEncryption", "Key"), "([B[BI)[B", (void*)jsw_k10},
        {js_native_name("De", "cryptClass", "Bytes"), "([B[B[B[B[BI)[B", (void*)jsw_k14},
        {js_native_name("Sealed", "Binding", "Key"), "([B)Ljava/lang/String;", (void*)jsw_k15},
        {js_native_name("Decode", "Runtime", "Resource"), "([B)[B", (void*)jsw_k13},
        {js_native_name("Ex", "ecuteVm", "Resource"), "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;", (void*)jsw_r20},
        {js_native_name("Ex", "ecuteVmResource", "ByToken"), "(J[Ljava/lang/Object;)Ljava/lang/Object;", (void*)jsw_r22},
        {js_native_name("Ex", "ecuteVmResource", "Void"), "(J)V", (void*)jsw_r23},
        {js_native_name("Ex", "ecuteVmResource", "Int"), "(J)I", (void*)jsw_r25},
        {js_native_name("Ex", "ecuteVmResourceInt", "Int"), "(JI)I", (void*)jsw_r26},
        {js_native_name("Ex", "ecuteVmResourceInt", "Void"), "(JI)V", (void*)jsw_r24},
        {js_native_name("nativeExecuteAkenVmPage", "", ""), "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;", (void*)jsw_a0},
        {js_native_name("nativeDecodeAkenStringPage", "", ""), "([BI[B)[B", (void*)jsw_a1},
        {js_native_name("nativeReadAkenClassPage", "", ""), "([BI[B)[B", (void*)jsw_a2},
        {js_native_name("nativeMapAkenNativeChunk", "", ""), "([BI[B)[B", (void*)jsw_a3},
    };
    if (!js_register_native_group(env, js_helper_owner("Jni", "Micro", "kernel", "Helper"), jni_microkernel_methods, (int)(sizeof(jni_microkernel_methods) / sizeof(jni_microkernel_methods[0])), 1)) return 0;
    return js_register_optional_natives(env);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    if (reserved == JS_SHELL_MANUAL_MAP_RESERVED) js_jni_runtime_manual_mapped_shell = 1;
    if (!js_protected_section_enter()) return JNI_ERR;
    js_native_anti_dump_harden();
    js_vm_cache_lock_init();
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        (void)js_protected_section_leave();
        return JNI_ERR;
    }
    if (!js_jni_cache_init(env)) {
        (void)js_protected_section_leave();
        return JNI_ERR;
    }
    int ok = 1;
    if (!js_jni_runtime_manual_mapped_shell) {
        ok = js_register_all_natives(env);
        if (ok && (*env)->ExceptionCheck(env)) {
            js_vm_clear_exception(env);
            ok = 0;
        }
    }
    if (ok) js_vm_mark_hot_integrity_baseline_clean();
    if (!ok) js_jni_cache_destroy(env);
    if (!js_protected_section_leave()) ok = 0;
    return ok ? JNI_VERSION_1_6 : JNI_ERR;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)reserved;
    if (js_jni_runtime_manual_mapped_shell) return;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) env = NULL;
    js_runtime_on_unload_cleanup(env);
    js_vm_cache_lock_destroy();
}
