#include "js_jni_runtime.h"
#include "js_aken_page_locator.inc"
#include "js_antidebug.h"
#include "js_protected_section.h"
#include "js_vm_core.h"
#include "js_vm_resource.h"
#include "js_crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(JS_AKEN_JNI_FIXTURE_DIAGNOSTICS)
#include <stdio.h>

static void js_aken_jni_fixture_onload_failure(const char *stage) {
    fputs("AKEN_JNI_ONLOAD_FAIL:", stderr);
    fputs(stage, stderr);
    fputc('\n', stderr);
    fflush(stderr);
}
#define JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE(stage) js_aken_jni_fixture_onload_failure(stage)
#else
#define JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE(stage) ((void)0)
#endif

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

static int js_aken_bridge_request_shape_is_valid(
    JNIEnv *env,
    jbyteArray encoded_handle,
    jint page_index,
    jbyteArray call_site_proof
) {
    if (!env || !encoded_handle || !call_site_proof || page_index < 0 ||
        (*env)->GetArrayLength(env, encoded_handle) != (jsize)JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE ||
        (*env)->GetArrayLength(env, call_site_proof) <= 0 ||
        (*env)->GetArrayLength(env, call_site_proof) > (jsize)JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE ||
        (*env)->ExceptionCheck(env)) {
        return 0;
    }
    return 1;
}

static int js_aken_bridge_request_is_valid(JNIEnv *env, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof) {
    if (!js_aken_bridge_request_shape_is_valid(env, encoded_handle, page_index, call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN page request is invalid");
        return 0;
    }
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
        !binding->evaluator_fingerprint ||
        binding->evaluator_fingerprint_len != JS_AKEN_EVALUATOR_STATE_WIDTH ||
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

/*
 * AKEN v4 generated current-page locator parser.  The include remains opaque
 * compiler input: every borrowed frame is constrained to exactly one record,
 * the complete table geometry is validated before a lookup succeeds, and no
 * function here decodes a resource or creates a catalog surface.
 */
#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_DOMAIN \
    "AKEN-v4-native-page-locator-compile-input-v1"

static int js_aken_native_page_locator_record_is_well_formed(
    const js_aken_native_page_locator_record *record,
    int require_successful_parse
) {
    if (!record || (require_successful_parse && record->parsed != 1u) ||
        !js_aken_native_page_envelope_kind_is_valid(record->resource_kind) || record->page_index < 0) {
        return 0;
    }
    if (!record->encoded_handle ||
        record->encoded_handle_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE ||
        !record->native_envelope || record->native_envelope_len == 0u ||
        record->native_envelope_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE ||
        !record->descriptor_encoding || record->descriptor_encoding_len == 0u ||
        record->descriptor_encoding_len > JS_AKEN_NATIVE_PAGE_DESCRIPTOR_MAX_SIZE ||
        !record->route_encoding || record->route_encoding_len == 0u ||
        record->route_encoding_len > JS_AKEN_NATIVE_PAGE_ROUTE_MAX_SIZE) {
        return 0;
    }
    return 1;
}

static int js_aken_native_page_locator_digest_record(
    const js_aken_native_page_locator_record *record,
    unsigned char out_binding[JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_SIZE]
) {
    static const unsigned char domain[] = JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_DOMAIN;
    js_sha256_ctx ctx;
    int ok = 0;
    if (!out_binding) return 0;
    js_vbc4_wipe_volatile(out_binding, JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_SIZE);
    memset(&ctx, 0, sizeof(ctx));
    if (!js_aken_native_page_locator_record_is_well_formed(record, 0)) goto cleanup;
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, domain, (int)(sizeof(domain) - 1u));
    js_aken_native_page_envelope_update_u64be(&ctx, record->entry_token);
    js_sha256_update(&ctx, &record->resource_kind, 1);
    js_aken_native_page_envelope_update_u32be(&ctx, (uint32_t)record->page_index);
    if (!js_aken_native_page_envelope_update_framed(
            &ctx,
            record->encoded_handle,
            record->encoded_handle_len) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            record->native_envelope,
            record->native_envelope_len) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            record->descriptor_encoding,
            record->descriptor_encoding_len) ||
        !js_aken_native_page_envelope_update_framed(
            &ctx,
            record->route_encoding,
            record->route_encoding_len)) {
        goto cleanup;
    }
    js_sha256_final(&ctx, out_binding);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    if (!ok) js_vbc4_wipe_volatile(out_binding, JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_SIZE);
    return ok;
}

JS_HIDDEN void js_aken_native_page_locator_record_wipe(js_aken_native_page_locator_record *record) {
    if (!record) return;
    js_vbc4_wipe_volatile(record, sizeof(*record));
}

static int js_aken_native_page_locator_record_parse(
    const unsigned char *encoded_record,
    size_t encoded_record_len,
    js_aken_native_page_locator_record *out_record
) {
    js_aken_native_page_envelope_reader reader = {0};
    unsigned char received_binding[JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_SIZE] = {0};
    unsigned char expected_binding[JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_SIZE] = {0};
    uint8_t record_version = 0u;
    uint32_t page_index = 0u;
    uint32_t encoded_handle_len = 0u;
    uint32_t native_envelope_len = 0u;
    uint32_t descriptor_encoding_len = 0u;
    uint32_t route_encoding_len = 0u;
    int ok = 0;
    if (!out_record) goto cleanup;
    js_aken_native_page_locator_record_wipe(out_record);
    if (!encoded_record || encoded_record_len == 0u ||
        encoded_record_len > JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_RECORD_SIZE ||
        JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_FORMAT_VERSION != JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_VERSION) {
        goto cleanup;
    }
    reader.bytes = encoded_record;
    reader.length = encoded_record_len;
    reader.offset = 0u;
    if (!js_aken_native_page_envelope_reader_read_u8(&reader, &record_version) ||
        record_version != JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_VERSION ||
        !js_aken_native_page_envelope_reader_read_u64be(&reader, &out_record->entry_token) ||
        !js_aken_native_page_envelope_reader_read_u8(&reader, &out_record->resource_kind) ||
        !js_aken_native_page_envelope_kind_is_valid(out_record->resource_kind) ||
        !js_aken_native_page_envelope_reader_read_u32be(&reader, &page_index) ||
        page_index > (uint32_t)INT_MAX) {
        goto cleanup;
    }
    out_record->page_index = (jint)page_index;
    if (!js_aken_native_page_envelope_reader_read_u32be(&reader, &encoded_handle_len) ||
        encoded_handle_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE ||
        !js_aken_native_page_envelope_reader_read_ref(
            &reader,
            &out_record->encoded_handle,
            (size_t)encoded_handle_len) ||
        !js_aken_native_page_envelope_reader_read_u32be(&reader, &native_envelope_len) ||
        native_envelope_len == 0u || native_envelope_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE ||
        !js_aken_native_page_envelope_reader_read_ref(
            &reader,
            &out_record->native_envelope,
            (size_t)native_envelope_len) ||
        !js_aken_native_page_envelope_reader_read_u32be(&reader, &descriptor_encoding_len) ||
        descriptor_encoding_len == 0u || descriptor_encoding_len > JS_AKEN_NATIVE_PAGE_DESCRIPTOR_MAX_SIZE ||
        !js_aken_native_page_envelope_reader_read_ref(
            &reader,
            &out_record->descriptor_encoding,
            (size_t)descriptor_encoding_len) ||
        !js_aken_native_page_envelope_reader_read_u32be(&reader, &route_encoding_len) ||
        route_encoding_len == 0u || route_encoding_len > JS_AKEN_NATIVE_PAGE_ROUTE_MAX_SIZE ||
        !js_aken_native_page_envelope_reader_read_ref(
            &reader,
            &out_record->route_encoding,
            (size_t)route_encoding_len) ||
        !js_aken_native_page_envelope_reader_read_bytes(
            &reader,
            received_binding,
            sizeof(received_binding)) ||
        reader.offset != reader.length) {
        goto cleanup;
    }
    out_record->encoded_handle_len = (size_t)encoded_handle_len;
    out_record->native_envelope_len = (size_t)native_envelope_len;
    out_record->descriptor_encoding_len = (size_t)descriptor_encoding_len;
    out_record->route_encoding_len = (size_t)route_encoding_len;
    if (!js_aken_native_page_locator_record_is_well_formed(out_record, 0) ||
        !js_aken_native_page_locator_digest_record(out_record, expected_binding) ||
        !js_aken_native_page_envelope_constant_time_equal(
            received_binding,
            expected_binding,
            sizeof(received_binding))) {
        goto cleanup;
    }
    out_record->parsed = 1u;
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(received_binding, sizeof(received_binding));
    js_vbc4_wipe_volatile(expected_binding, sizeof(expected_binding));
    js_vbc4_wipe_volatile(&reader, sizeof(reader));
    if (!ok && out_record) js_aken_native_page_locator_record_wipe(out_record);
    return ok;
}

JS_HIDDEN int js_aken_native_page_locator_lookup(
    const js_aken_native_page_request *request,
    js_aken_native_page_locator_record *out_record
) {
    const unsigned char *blob = (const unsigned char *)(const void *)js_aken_native_page_locator_blob;
    const size_t record_count = (size_t)JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT;
    const size_t blob_size = (size_t)JS_AKEN_NATIVE_PAGE_LOCATOR_BLOB_SIZE;
    js_aken_native_page_locator_record candidate = {0};
    js_aken_native_page_locator_record matched = {0};
    size_t expected_offset = 0u;
    size_t match_count = 0u;
    size_t record_index;
    int ok = 0;
    if (!out_record) goto cleanup;
    js_aken_native_page_locator_record_wipe(out_record);
    if (!js_aken_native_page_request_is_valid(request) ||
        record_count == 0u || record_count > JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_RECORD_COUNT ||
        blob_size == 0u || blob_size > JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_BLOB_SIZE ||
        JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_FORMAT_VERSION != JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_VERSION) {
        goto cleanup;
    }
    for (record_index = 0u; record_index < record_count; ++record_index) {
        const size_t offset = (size_t)js_aken_native_page_locator_record_offsets[record_index];
        const size_t length = (size_t)js_aken_native_page_locator_record_lengths[record_index];
        if (offset != expected_offset || length == 0u ||
            length > JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_RECORD_SIZE ||
            offset > blob_size || length > blob_size - offset) {
            goto cleanup;
        }
        if (!js_aken_native_page_locator_record_parse(blob + offset, length, &candidate)) goto cleanup;
        if (candidate.entry_token == request->entry_token &&
            candidate.resource_kind == request->resource_kind &&
            candidate.page_index == request->page_index &&
            js_aken_native_page_envelope_constant_time_equal(
                candidate.encoded_handle,
                request->encoded_handle,
                JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE)) {
            if (match_count == 0u) matched = candidate;
            ++match_count;
        }
        expected_offset += length;
        js_aken_native_page_locator_record_wipe(&candidate);
    }
    if (expected_offset != blob_size || match_count != 1u) goto cleanup;
    *out_record = matched;
    ok = 1;
cleanup:
    js_aken_native_page_locator_record_wipe(&candidate);
    js_aken_native_page_locator_record_wipe(&matched);
    if (!ok && out_record) js_aken_native_page_locator_record_wipe(out_record);
    return ok;
}

JS_HIDDEN int js_aken_native_page_locator_resolve(
    const js_aken_native_page_locator_record *record,
    const js_aken_native_page_envelope *envelope,
    js_aken_native_page_resolved_descriptor *out_resolved
) {
    int identity_matches = 0;
    int ok = 0;
    if (!out_resolved) goto cleanup;
    js_vbc4_wipe_volatile(out_resolved, sizeof(*out_resolved));
    if (!js_aken_native_page_locator_record_is_well_formed(record, 1) ||
        !js_aken_native_page_envelope_record_is_well_formed(envelope, 1)) {
        goto cleanup;
    }
    identity_matches = record->entry_token == envelope->entry_token &&
        record->resource_kind == envelope->resource_kind &&
        record->page_index == envelope->page_index &&
        js_aken_native_page_envelope_constant_time_equal(
            record->encoded_handle,
            envelope->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE);
    if (!identity_matches) goto cleanup;
    out_resolved->resource_kind = record->resource_kind;
    out_resolved->page_index = record->page_index;
    out_resolved->encoded_handle = record->encoded_handle;
    out_resolved->encoded_handle_len = record->encoded_handle_len;
    out_resolved->locator_token = envelope->locator_token;
    out_resolved->locator_token_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE;
    out_resolved->evaluator_fingerprint = envelope->evaluator_fingerprint;
    out_resolved->evaluator_fingerprint_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE;
    out_resolved->artifact_commitment = envelope->artifact_commitment;
    out_resolved->artifact_commitment_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE;
    out_resolved->descriptor_encoding = record->descriptor_encoding;
    out_resolved->descriptor_encoding_len = record->descriptor_encoding_len;
    out_resolved->route_encoding = record->route_encoding;
    out_resolved->route_encoding_len = record->route_encoding_len;
    ok = js_aken_native_page_envelope_verify_resolved_bindings(envelope, out_resolved);
cleanup:
    if (!ok && out_resolved) js_vbc4_wipe_volatile(out_resolved, sizeof(*out_resolved));
    return ok;
}

/*
 * Current-page-only AKEN v4 runtime descriptor parser.  The Kotlin descriptor
 * format is deliberately parsed here instead of through a Java object graph:
 * this gives the native terminal a single, non-enumerable route/proof/evaluator
 * view whose borrowed bytes remain scoped to the already matched locator row.
 */
#define JS_AKEN_DESCRIPTOR_VERSION 1u
#define JS_AKEN_DESCRIPTOR_MAX_SIZE (384u * 1024u)
#define JS_AKEN_DESCRIPTOR_MAX_ROUTE_SIZE (128u * 1024u)
#define JS_AKEN_DESCRIPTOR_MAX_PROOF_SIZE (160u * 1024u)
#define JS_AKEN_DESCRIPTOR_MAX_PLAN_SIZE (128u * 1024u)
#define JS_AKEN_DESCRIPTOR_MAX_FRAGMENT_SIZE (12u * 1024u)
#define JS_AKEN_DESCRIPTOR_MAX_RESOURCE_PATH_SIZE 4096u
#define JS_AKEN_DESCRIPTOR_MAX_VARIANT_SIZE 256u
#define JS_AKEN_DESCRIPTOR_MAX_MERKLE_DEPTH 64u
#define JS_AKEN_DESCRIPTOR_MAX_CALL_SITE_PROOF_SIZE 4096u
#define JS_AKEN_DESCRIPTOR_EVALUATOR_PLAN_VERSION 1u
#define JS_AKEN_DESCRIPTOR_FRAGMENT_VERSION 1u
#define JS_AKEN_DESCRIPTOR_IDENTITY_VERSION 1u
#define JS_AKEN_DESCRIPTOR_ROUTE_VERSION 1u
#define JS_AKEN_DESCRIPTOR_PROOF_VERSION 1u

static const unsigned char JS_AKEN_DESCRIPTOR_EVALUATOR_DOMAIN[] = "AKEN-v4-evaluator-graph";
static const unsigned char JS_AKEN_DESCRIPTOR_INTEGRITY_LEAF_DOMAIN[] = "AKEN-v4-integrity-leaf";
static const unsigned char JS_AKEN_DESCRIPTOR_INTEGRITY_NODE_DOMAIN[] = "AKEN-v4-integrity-node";

/* These terminal-codec helpers are defined below the descriptor parser. */
static int js_aken_native_page_open_ascii_equal(
    const unsigned char *left,
    size_t left_len,
    const unsigned char *right,
    size_t right_len
);
static int js_aken_native_page_open_layout_parse(
    const unsigned char *layout,
    size_t layout_len,
    size_t *out_prefix_len,
    size_t *out_suffix_len,
    int *out_header_after_body
);

typedef struct {
    const unsigned char *bytes;
    size_t length;
    size_t offset;
} js_aken_native_descriptor_cursor;

typedef struct {
    uint8_t resource_kind;
    jint page_index;
    const unsigned char *encoded_handle;
    const unsigned char *locator_token;
    const unsigned char *evaluator_fingerprint;
    const unsigned char *logical_identity;
    size_t logical_identity_len;
} js_aken_native_descriptor_identity;

typedef struct {
    js_aken_native_descriptor_identity identity;
    const unsigned char *identity_encoding;
    size_t identity_encoding_len;
    const unsigned char *resource_path;
    size_t resource_path_len;
    uint32_t resource_offset;
    uint32_t stored_length;
    const unsigned char *codec_variant;
    size_t codec_variant_len;
    const unsigned char *layout_variant;
    size_t layout_variant_len;
} js_aken_native_descriptor_route;

typedef struct {
    js_aken_native_descriptor_identity identity;
    const unsigned char *identity_encoding;
    size_t identity_encoding_len;
    const unsigned char *artifact_commitment;
    const unsigned char *mesh_root;
    const unsigned char *leaf_digest;
    const unsigned char *merkle_siblings[JS_AKEN_DESCRIPTOR_MAX_MERKLE_DEPTH];
    uint8_t merkle_sibling_is_left[JS_AKEN_DESCRIPTOR_MAX_MERKLE_DEPTH];
    size_t merkle_sibling_count;
    const unsigned char *call_site_proof;
    size_t call_site_proof_len;
    const unsigned char *codec_variant;
    size_t codec_variant_len;
    const unsigned char *layout_variant;
    size_t layout_variant_len;
} js_aken_native_descriptor_proof;

static int js_aken_native_descriptor_cursor_remaining(
    const js_aken_native_descriptor_cursor *cursor,
    size_t amount
) {
    return cursor && amount <= cursor->length && cursor->offset <= cursor->length - amount;
}

static int js_aken_native_descriptor_read_u8(
    js_aken_native_descriptor_cursor *cursor,
    uint8_t *out_value
) {
    if (!cursor || !out_value || !js_aken_native_descriptor_cursor_remaining(cursor, 1u)) return 0;
    *out_value = cursor->bytes[cursor->offset++];
    return 1;
}

static int js_aken_native_descriptor_read_u32be(
    js_aken_native_descriptor_cursor *cursor,
    uint32_t *out_value
) {
    const unsigned char *value = NULL;
    if (!cursor || !out_value || !js_aken_native_descriptor_cursor_remaining(cursor, 4u)) return 0;
    value = cursor->bytes + cursor->offset;
    *out_value = ((uint32_t)value[0] << 24) |
        ((uint32_t)value[1] << 16) |
        ((uint32_t)value[2] << 8) |
        (uint32_t)value[3];
    cursor->offset += 4u;
    return 1;
}

static int js_aken_native_descriptor_read_fixed(
    js_aken_native_descriptor_cursor *cursor,
    size_t length,
    const unsigned char **out_value
) {
    if (!cursor || !out_value || !js_aken_native_descriptor_cursor_remaining(cursor, length)) return 0;
    *out_value = cursor->bytes + cursor->offset;
    cursor->offset += length;
    return 1;
}

static int js_aken_native_descriptor_read_frame(
    js_aken_native_descriptor_cursor *cursor,
    size_t maximum_length,
    int allow_empty,
    const unsigned char **out_value,
    size_t *out_length
) {
    uint32_t encoded_length = 0u;
    size_t length = 0u;
    if (!cursor || !out_value || !out_length || !js_aken_native_descriptor_read_u32be(cursor, &encoded_length)) {
        return 0;
    }
    length = (size_t)encoded_length;
    if (length > maximum_length || (!allow_empty && length == 0u) ||
        !js_aken_native_descriptor_cursor_remaining(cursor, length)) {
        return 0;
    }
    *out_value = cursor->bytes + cursor->offset;
    *out_length = length;
    cursor->offset += length;
    return 1;
}

static int js_aken_native_descriptor_cursor_finished(const js_aken_native_descriptor_cursor *cursor) {
    return cursor && cursor->offset == cursor->length;
}

static int js_aken_native_descriptor_parse_identity(
    const unsigned char *encoded,
    size_t encoded_len,
    js_aken_native_descriptor_identity *out_identity
) {
    js_aken_native_descriptor_cursor cursor;
    uint8_t version = 0u;
    uint8_t kind = 0u;
    uint32_t page = 0u;
    if (!out_identity) return 0;
    js_vbc4_wipe_volatile(out_identity, sizeof(*out_identity));
    if (!encoded || encoded_len == 0u || encoded_len > (96u * 1024u)) return 0;
    cursor.bytes = encoded;
    cursor.length = encoded_len;
    cursor.offset = 0u;
    if (!js_aken_native_descriptor_read_u8(&cursor, &version) || version != JS_AKEN_DESCRIPTOR_IDENTITY_VERSION ||
        !js_aken_native_descriptor_read_u8(&cursor, &kind) || kind < 1u || kind > 4u ||
        !js_aken_native_descriptor_read_u32be(&cursor, &page) || page > (uint32_t)INT_MAX ||
        !js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE, &out_identity->encoded_handle) ||
        !js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE, &out_identity->locator_token) ||
        !js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE, &out_identity->evaluator_fingerprint) ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_EVALUATOR_MAX_LOGICAL_IDENTITY_BYTES,
            0,
            &out_identity->logical_identity,
            &out_identity->logical_identity_len) ||
        !js_aken_native_descriptor_cursor_finished(&cursor)) {
        js_vbc4_wipe_volatile(out_identity, sizeof(*out_identity));
        return 0;
    }
    out_identity->resource_kind = kind;
    out_identity->page_index = (jint)page;
    return 1;
}

static int js_aken_native_descriptor_identity_equal(
    const js_aken_native_descriptor_identity *left,
    const js_aken_native_descriptor_identity *right
) {
    return left && right &&
        left->resource_kind == right->resource_kind &&
        left->page_index == right->page_index &&
        left->logical_identity_len == right->logical_identity_len &&
        js_aken_native_page_envelope_constant_time_equal(
            left->encoded_handle,
            right->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            left->locator_token,
            right->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            left->evaluator_fingerprint,
            right->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            left->logical_identity,
            right->logical_identity,
            left->logical_identity_len);
}

static int js_aken_native_descriptor_identity_matches_current(
    const js_aken_native_descriptor_identity *identity,
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved
) {
    return identity && request && envelope && resolved &&
        identity->resource_kind == request->resource_kind &&
        identity->resource_kind == envelope->resource_kind &&
        identity->resource_kind == resolved->resource_kind &&
        identity->page_index == request->page_index &&
        identity->page_index == envelope->page_index &&
        identity->page_index == resolved->page_index &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->encoded_handle,
            request->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->encoded_handle,
            envelope->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->encoded_handle,
            resolved->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->locator_token,
            envelope->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->locator_token,
            resolved->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->evaluator_fingerprint,
            envelope->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            identity->evaluator_fingerprint,
            resolved->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
}

static int js_aken_native_descriptor_route_path_is_valid(
    const unsigned char *path,
    size_t path_len
) {
    size_t segment_start = 0u;
    if (!path || path_len == 0u || path_len > JS_AKEN_DESCRIPTOR_MAX_RESOURCE_PATH_SIZE ||
        path[0] == (unsigned char)'/' || path[path_len - 1u] == (unsigned char)'/') {
        return 0;
    }
    for (size_t index = 0u; index <= path_len; index++) {
        const int at_end = index == path_len;
        const int separator = !at_end && path[index] == (unsigned char)'/';
        if (!at_end && (path[index] == 0u || path[index] == (unsigned char)'\\')) return 0;
        if (!at_end && !separator) continue;
        if (index == segment_start ||
            (index - segment_start == 1u && path[segment_start] == (unsigned char)'.') ||
            (index - segment_start == 2u && path[segment_start] == (unsigned char)'.' &&
                path[segment_start + 1u] == (unsigned char)'.')) {
            return 0;
        }
        segment_start = index + 1u;
    }
    return 1;
}

static int js_aken_native_descriptor_parse_route(
    const unsigned char *encoded,
    size_t encoded_len,
    js_aken_native_descriptor_route *out_route
) {
    js_aken_native_descriptor_cursor cursor;
    uint8_t version = 0u;
    uint32_t offset = 0u;
    uint32_t length = 0u;
    const unsigned char *identity = NULL;
    size_t identity_len = 0u;
    if (!out_route) return 0;
    js_vbc4_wipe_volatile(out_route, sizeof(*out_route));
    if (!encoded || encoded_len == 0u || encoded_len > JS_AKEN_DESCRIPTOR_MAX_ROUTE_SIZE) return 0;
    cursor.bytes = encoded;
    cursor.length = encoded_len;
    cursor.offset = 0u;
    if (!js_aken_native_descriptor_read_u8(&cursor, &version) || version != JS_AKEN_DESCRIPTOR_ROUTE_VERSION ||
        !js_aken_native_descriptor_read_frame(&cursor, 96u * 1024u, 0, &identity, &identity_len) ||
        !js_aken_native_descriptor_parse_identity(identity, identity_len, &out_route->identity) ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_DESCRIPTOR_MAX_RESOURCE_PATH_SIZE,
            0,
            &out_route->resource_path,
            &out_route->resource_path_len) ||
        !js_aken_native_descriptor_read_u32be(&cursor, &offset) || offset > (uint32_t)INT_MAX ||
        !js_aken_native_descriptor_read_u32be(&cursor, &length) || length == 0u || length > (uint32_t)INT_MAX ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_DESCRIPTOR_MAX_VARIANT_SIZE,
            0,
            &out_route->codec_variant,
            &out_route->codec_variant_len) ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_DESCRIPTOR_MAX_VARIANT_SIZE,
            0,
            &out_route->layout_variant,
            &out_route->layout_variant_len) ||
        !js_aken_native_descriptor_cursor_finished(&cursor)) {
        js_vbc4_wipe_volatile(out_route, sizeof(*out_route));
        return 0;
    }
    out_route->identity_encoding = identity;
    out_route->identity_encoding_len = identity_len;
    out_route->resource_offset = offset;
    out_route->stored_length = length;
    return 1;
}

static int js_aken_native_descriptor_parse_proof(
    const unsigned char *encoded,
    size_t encoded_len,
    js_aken_native_descriptor_proof *out_proof
) {
    js_aken_native_descriptor_cursor cursor;
    uint8_t version = 0u;
    uint32_t sibling_count = 0u;
    const unsigned char *identity = NULL;
    size_t identity_len = 0u;
    if (!out_proof) return 0;
    js_vbc4_wipe_volatile(out_proof, sizeof(*out_proof));
    if (!encoded || encoded_len == 0u || encoded_len > JS_AKEN_DESCRIPTOR_MAX_PROOF_SIZE) return 0;
    cursor.bytes = encoded;
    cursor.length = encoded_len;
    cursor.offset = 0u;
    if (!js_aken_native_descriptor_read_u8(&cursor, &version) || version != JS_AKEN_DESCRIPTOR_PROOF_VERSION ||
        !js_aken_native_descriptor_read_frame(&cursor, 96u * 1024u, 0, &identity, &identity_len) ||
        !js_aken_native_descriptor_parse_identity(identity, identity_len, &out_proof->identity) ||
        !js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE, &out_proof->artifact_commitment) ||
        !js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE, &out_proof->mesh_root) ||
        !js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE, &out_proof->leaf_digest) ||
        !js_aken_native_descriptor_read_u32be(&cursor, &sibling_count) || sibling_count > JS_AKEN_DESCRIPTOR_MAX_MERKLE_DEPTH) {
        js_vbc4_wipe_volatile(out_proof, sizeof(*out_proof));
        return 0;
    }
    for (uint32_t index = 0u; index < sibling_count; index++) {
        const unsigned char *sibling = NULL;
        uint8_t direction = 0u;
        if (!js_aken_native_descriptor_read_fixed(&cursor, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE, &sibling) ||
            !js_aken_native_descriptor_read_u8(&cursor, &direction) || direction > 1u) {
            js_vbc4_wipe_volatile(out_proof, sizeof(*out_proof));
            return 0;
        }
        out_proof->merkle_siblings[index] = sibling;
        out_proof->merkle_sibling_is_left[index] = direction;
    }
    out_proof->identity_encoding = identity;
    out_proof->identity_encoding_len = identity_len;
    out_proof->merkle_sibling_count = sibling_count;
    if (!js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_DESCRIPTOR_MAX_CALL_SITE_PROOF_SIZE,
            0,
            &out_proof->call_site_proof,
            &out_proof->call_site_proof_len) ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_DESCRIPTOR_MAX_VARIANT_SIZE,
            0,
            &out_proof->codec_variant,
            &out_proof->codec_variant_len) ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_DESCRIPTOR_MAX_VARIANT_SIZE,
            0,
            &out_proof->layout_variant,
            &out_proof->layout_variant_len) ||
        !js_aken_native_descriptor_cursor_finished(&cursor)) {
        js_vbc4_wipe_volatile(out_proof, sizeof(*out_proof));
        return 0;
    }
    return 1;
}

static int js_aken_native_descriptor_parse_fragment(
    const unsigned char *encoded,
    size_t encoded_len,
    uint8_t expected_role,
    jint expected_ordinal_min,
    jint expected_ordinal_max,
    js_aken_evaluator_fragment *out_fragment,
    uint32_t permutations[JS_AKEN_EVALUATOR_STATE_WIDTH]
) {
    js_aken_native_descriptor_cursor cursor;
    uint8_t version = 0u;
    uint8_t role = 0u;
    uint32_t ordinal = 0u;
    uint32_t family = 0u;
    uint32_t table_length = 0u;
    if (!out_fragment || !permutations || !encoded || encoded_len == 0u || encoded_len > JS_AKEN_DESCRIPTOR_MAX_FRAGMENT_SIZE) {
        return 0;
    }
    js_vbc4_wipe_volatile(out_fragment, sizeof(*out_fragment));
    js_vbc4_wipe_volatile(permutations, JS_AKEN_EVALUATOR_STATE_WIDTH * sizeof(permutations[0]));
    cursor.bytes = encoded;
    cursor.length = encoded_len;
    cursor.offset = 0u;
    if (!js_aken_native_descriptor_read_u8(&cursor, &version) || version != JS_AKEN_DESCRIPTOR_FRAGMENT_VERSION ||
        !js_aken_native_descriptor_read_u8(&cursor, &role) || role != expected_role ||
        !js_aken_native_descriptor_read_u32be(&cursor, &ordinal) || ordinal > (uint32_t)INT_MAX ||
        (jint)ordinal < expected_ordinal_min || (jint)ordinal > expected_ordinal_max ||
        !js_aken_native_descriptor_read_u32be(&cursor, &family) || family >= 16u) {
        goto cleanup;
    }
    out_fragment->ordinal = (jint)ordinal;
    out_fragment->family = (jint)family;
    if (!js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES,
            0,
            &out_fragment->shape,
            &out_fragment->shape_len) ||
        !js_aken_native_descriptor_read_frame(
            &cursor,
            JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES,
            0,
            &out_fragment->call_token,
            &out_fragment->call_token_len) ||
        !js_aken_native_descriptor_read_u32be(&cursor, &table_length) ||
        table_length != JS_AKEN_EVALUATOR_STATE_WIDTH) {
        goto cleanup;
    }
    for (uint32_t index = 0u; index < table_length; index++) {
        if (!js_aken_native_descriptor_read_u32be(&cursor, &permutations[index]) ||
            permutations[index] >= JS_AKEN_EVALUATOR_STATE_WIDTH) {
            goto cleanup;
        }
    }
    if (!js_aken_native_descriptor_cursor_finished(&cursor)) goto cleanup;
    out_fragment->table_permutation = permutations;
    out_fragment->table_permutation_len = JS_AKEN_EVALUATOR_STATE_WIDTH;
    if (!js_aken_evaluator_fragment_is_valid(out_fragment)) goto cleanup;
    return 1;
cleanup:
    js_vbc4_wipe_volatile(out_fragment, sizeof(*out_fragment));
    js_vbc4_wipe_volatile(permutations, JS_AKEN_EVALUATOR_STATE_WIDTH * sizeof(permutations[0]));
    return 0;
}

static int js_aken_native_descriptor_update_fragment_group(
    js_sha256_ctx *ctx,
    uint8_t role,
    const js_aken_evaluator_fragment *fragments,
    size_t fragment_count
) {
    if (!ctx || !fragments || fragment_count > (size_t)INT_MAX) return 0;
    js_aken_evaluator_update_u32be(ctx, (uint32_t)fragment_count);
    for (size_t index = 0u; index < fragment_count; index++) {
        const js_aken_evaluator_fragment *fragment = &fragments[index];
        if (!js_aken_evaluator_fragment_is_valid(fragment)) return 0;
        js_sha256_update(ctx, &role, 1);
        js_aken_evaluator_update_u32be(ctx, (uint32_t)index);
        js_aken_evaluator_update_u32be(ctx, (uint32_t)fragment->ordinal);
        js_aken_evaluator_update_u32be(ctx, (uint32_t)fragment->family);
        if (!js_aken_evaluator_update_framed(ctx, fragment->shape, fragment->shape_len)) return 0;
        js_aken_evaluator_update_u32be(ctx, (uint32_t)fragment->table_permutation_len);
        for (size_t table_index = 0u; table_index < fragment->table_permutation_len; table_index++) {
            js_aken_evaluator_update_u32be(ctx, fragment->table_permutation[table_index]);
        }
        if (!js_aken_evaluator_update_framed(ctx, fragment->call_token, fragment->call_token_len)) return 0;
    }
    return 1;
}

static int js_aken_native_descriptor_fingerprint_matches(const js_aken_native_page_descriptor_view *view) {
    js_sha256_ctx ctx;
    unsigned char actual[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    int ok = 0;
    if (!view || !js_aken_evaluator_binding_is_valid(&view->binding) ||
        !js_aken_evaluator_graph_is_valid(view->fragments, JS_AKEN_EVALUATOR_FRAGMENT_COUNT)) {
        goto cleanup;
    }
    js_sha256_init(&ctx);
    js_sha256_update(
        &ctx,
        JS_AKEN_DESCRIPTOR_EVALUATOR_DOMAIN,
        (int)(sizeof(JS_AKEN_DESCRIPTOR_EVALUATOR_DOMAIN) - 1u));
    js_sha256_update(&ctx, &view->binding.kind_id, 1);
    if (!js_aken_evaluator_update_framed(&ctx, view->binding.logical_identity, view->binding.logical_identity_len)) {
        goto cleanup;
    }
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)view->binding.page_index);
    js_aken_evaluator_update_u32be(&ctx, (uint32_t)view->binding.target_size);
    if (!js_aken_evaluator_update_framed(&ctx, view->binding.codec_variant, view->binding.codec_variant_len) ||
        !js_aken_evaluator_update_framed(&ctx, view->binding.layout_variant, view->binding.layout_variant_len) ||
        !js_aken_evaluator_update_framed(&ctx, view->binding.encoded_handle, view->binding.encoded_handle_len) ||
        !js_aken_evaluator_update_framed(&ctx, view->binding.locator_token, view->binding.locator_token_len) ||
        !js_aken_native_descriptor_update_fragment_group(&ctx, 1u, &view->fragments[0], 3u) ||
        !js_aken_native_descriptor_update_fragment_group(&ctx, 2u, &view->fragments[3], 3u) ||
        !js_aken_native_descriptor_update_fragment_group(&ctx, 3u, &view->fragments[6], 1u)) {
        goto cleanup;
    }
    js_sha256_final(&ctx, actual);
    ok = js_aken_native_page_envelope_constant_time_equal(
        actual,
        view->binding.evaluator_fingerprint,
        JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
cleanup:
    js_vbc4_wipe_volatile(actual, sizeof(actual));
    return ok;
}

JS_HIDDEN void js_aken_native_page_descriptor_view_wipe(js_aken_native_page_descriptor_view *view) {
    if (!view) return;
    js_vbc4_wipe_volatile(view, sizeof(*view));
}

static int js_aken_native_descriptor_integrity_leaf(
    const unsigned char *identity,
    size_t identity_len,
    const unsigned char *payload,
    size_t payload_len,
    unsigned char out_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx ctx;
    if (!out_digest || !identity || identity_len == 0u || !payload || payload_len == 0u ||
        identity_len > (size_t)INT_MAX || payload_len > (size_t)INT_MAX) {
        return 0;
    }
    js_sha256_init(&ctx);
    js_sha256_update(
        &ctx,
        JS_AKEN_DESCRIPTOR_INTEGRITY_LEAF_DOMAIN,
        (int)(sizeof(JS_AKEN_DESCRIPTOR_INTEGRITY_LEAF_DOMAIN) - 1u));
    if (!js_aken_evaluator_update_framed(&ctx, identity, identity_len) ||
        !js_aken_evaluator_update_framed(&ctx, payload, payload_len)) {
        return 0;
    }
    js_sha256_final(&ctx, out_digest);
    return 1;
}

static int js_aken_native_descriptor_integrity_node(
    const unsigned char left[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE],
    const unsigned char right[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE],
    unsigned char out_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx ctx;
    if (!left || !right || !out_digest) return 0;
    js_sha256_init(&ctx);
    js_sha256_update(
        &ctx,
        JS_AKEN_DESCRIPTOR_INTEGRITY_NODE_DOMAIN,
        (int)(sizeof(JS_AKEN_DESCRIPTOR_INTEGRITY_NODE_DOMAIN) - 1u));
    if (!js_aken_evaluator_update_framed(&ctx, left, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_evaluator_update_framed(&ctx, right, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        return 0;
    }
    js_sha256_final(&ctx, out_digest);
    return 1;
}

JS_HIDDEN int js_aken_native_page_descriptor_verify_payload_mesh(
    const js_aken_native_page_descriptor_view *view,
    const unsigned char *encoded_payload,
    size_t encoded_payload_len
) {
    unsigned char current[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char next[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    int ok = 0;
    if (!view || view->parsed != 1u || !js_aken_evaluator_binding_is_valid(&view->binding) ||
        !view->leaf_identity_encoding || view->leaf_identity_encoding_len == 0u ||
        !view->mesh_root || !view->leaf_digest ||
        view->merkle_sibling_count > JS_AKEN_DESCRIPTOR_MAX_MERKLE_DEPTH ||
        !encoded_payload || encoded_payload_len == 0u) {
        goto cleanup;
    }
    if (!js_aken_native_descriptor_integrity_leaf(
            view->leaf_identity_encoding,
            view->leaf_identity_encoding_len,
            encoded_payload,
            encoded_payload_len,
            current) ||
        !js_aken_native_page_envelope_constant_time_equal(
            current,
            view->leaf_digest,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    for (size_t index = 0u; index < view->merkle_sibling_count; index++) {
        const unsigned char *sibling = view->merkle_siblings[index];
        if (!sibling || view->merkle_sibling_is_left[index] > 1u ||
            !js_aken_native_descriptor_integrity_node(
                view->merkle_sibling_is_left[index] ? sibling : current,
                view->merkle_sibling_is_left[index] ? current : sibling,
                next)) {
            goto cleanup;
        }
        memcpy(current, next, sizeof(current));
        js_vbc4_wipe_volatile(next, sizeof(next));
    }
    ok = js_aken_native_page_envelope_constant_time_equal(
        current,
        view->mesh_root,
        JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
cleanup:
    js_vbc4_wipe_volatile(current, sizeof(current));
    js_vbc4_wipe_volatile(next, sizeof(next));
    return ok;
}

JS_HIDDEN int js_aken_native_page_descriptor_parse_current(
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved,
    js_aken_native_page_descriptor_view *out_view
) {
    js_aken_native_descriptor_cursor descriptor_cursor;
    js_aken_native_descriptor_cursor plan_cursor;
    js_aken_native_descriptor_route route;
    js_aken_native_descriptor_proof proof;
    const unsigned char *route_bytes = NULL;
    const unsigned char *proof_bytes = NULL;
    const unsigned char *plan_bytes = NULL;
    const unsigned char *fingerprint = NULL;
    size_t route_len = 0u;
    size_t proof_len = 0u;
    size_t plan_len = 0u;
    uint8_t version = 0u;
    uint8_t plan_version = 0u;
    uint32_t target_size = 0u;
    size_t layout_prefix_len = 0u;
    size_t layout_suffix_len = 0u;
    int layout_header_after_body = 0;
    int ok = 0;
    if (!out_view) goto cleanup;
    js_aken_native_page_descriptor_view_wipe(out_view);
    js_vbc4_wipe_volatile(&route, sizeof(route));
    js_vbc4_wipe_volatile(&proof, sizeof(proof));
    if (!js_aken_native_page_request_is_valid(request) ||
        !js_aken_native_page_envelope_record_is_well_formed(envelope, 1) ||
        !js_aken_native_page_resolved_descriptor_is_well_formed(resolved) ||
        !js_aken_native_page_envelope_verify_resolved_bindings(envelope, resolved) ||
        !resolved->descriptor_encoding || resolved->descriptor_encoding_len == 0u ||
        resolved->descriptor_encoding_len > JS_AKEN_DESCRIPTOR_MAX_SIZE) {
        goto cleanup;
    }
    descriptor_cursor.bytes = resolved->descriptor_encoding;
    descriptor_cursor.length = resolved->descriptor_encoding_len;
    descriptor_cursor.offset = 0u;
    if (!js_aken_native_descriptor_read_u8(&descriptor_cursor, &version) || version != JS_AKEN_DESCRIPTOR_VERSION ||
        !js_aken_native_descriptor_read_frame(
            &descriptor_cursor,
            JS_AKEN_DESCRIPTOR_MAX_ROUTE_SIZE,
            0,
            &route_bytes,
            &route_len) ||
        !js_aken_native_descriptor_parse_route(route_bytes, route_len, &route) ||
        !js_aken_native_descriptor_read_frame(
            &descriptor_cursor,
            JS_AKEN_DESCRIPTOR_MAX_PROOF_SIZE,
            0,
            &proof_bytes,
            &proof_len) ||
        !js_aken_native_descriptor_parse_proof(proof_bytes, proof_len, &proof) ||
        !js_aken_native_descriptor_read_u32be(&descriptor_cursor, &target_size) || target_size > (uint32_t)INT_MAX ||
        !js_aken_evaluator_target_size_is_valid(route.identity.resource_kind, (jint)target_size) ||
        !js_aken_native_descriptor_read_frame(
            &descriptor_cursor,
            JS_AKEN_DESCRIPTOR_MAX_PLAN_SIZE,
            0,
            &plan_bytes,
            &plan_len) ||
        !js_aken_native_descriptor_cursor_finished(&descriptor_cursor)) {
        goto cleanup;
    }
    if (!js_aken_native_descriptor_identity_equal(&route.identity, &proof.identity) ||
        route.identity_encoding_len != proof.identity_encoding_len ||
        !js_aken_native_page_envelope_constant_time_equal(
            route.identity_encoding,
            proof.identity_encoding,
            route.identity_encoding_len) ||
        !js_aken_native_descriptor_identity_matches_current(&route.identity, request, envelope, resolved) ||
        !js_aken_native_descriptor_route_path_is_valid(route.resource_path, route.resource_path_len) ||
        !js_aken_native_page_open_ascii_equal(
            route.codec_variant,
            route.codec_variant_len,
            (const unsigned char *)"aes-256-gcm-v4",
            sizeof("aes-256-gcm-v4") - 1u) ||
        !js_aken_native_page_open_layout_parse(
            route.layout_variant,
            route.layout_variant_len,
            &layout_prefix_len,
            &layout_suffix_len,
            &layout_header_after_body) ||
        route.codec_variant_len != proof.codec_variant_len ||
        route.layout_variant_len != proof.layout_variant_len ||
        proof.call_site_proof_len != request->raw_call_site_proof_len ||
        !js_aken_native_page_envelope_constant_time_equal(
            route.codec_variant,
            proof.codec_variant,
            route.codec_variant_len) ||
        !js_aken_native_page_envelope_constant_time_equal(
            route.layout_variant,
            proof.layout_variant,
            route.layout_variant_len) ||
        !js_aken_native_page_envelope_constant_time_equal(
            proof.call_site_proof,
            request->raw_call_site_proof,
            proof.call_site_proof_len) ||
        !js_aken_native_page_envelope_constant_time_equal(
            proof.artifact_commitment,
            envelope->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            proof.artifact_commitment,
            resolved->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE)) {
        goto cleanup;
    }
    out_view->binding.kind_id = route.identity.resource_kind;
    out_view->binding.logical_identity = route.identity.logical_identity;
    out_view->binding.logical_identity_len = route.identity.logical_identity_len;
    out_view->binding.page_index = route.identity.page_index;
    out_view->binding.target_size = (jint)target_size;
    out_view->binding.codec_variant = route.codec_variant;
    out_view->binding.codec_variant_len = route.codec_variant_len;
    out_view->binding.layout_variant = route.layout_variant;
    out_view->binding.layout_variant_len = route.layout_variant_len;
    out_view->binding.encoded_handle = route.identity.encoded_handle;
    out_view->binding.encoded_handle_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE;
    out_view->binding.locator_token = route.identity.locator_token;
    out_view->binding.locator_token_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE;
    out_view->binding.artifact_commitment = proof.artifact_commitment;
    out_view->binding.artifact_commitment_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE;

    plan_cursor.bytes = plan_bytes;
    plan_cursor.length = plan_len;
    plan_cursor.offset = 0u;
    if (!js_aken_native_descriptor_read_u8(&plan_cursor, &plan_version) ||
        plan_version != JS_AKEN_DESCRIPTOR_EVALUATOR_PLAN_VERSION) {
        goto cleanup;
    }
    for (size_t index = 0u; index < JS_AKEN_EVALUATOR_FRAGMENT_COUNT; index++) {
        const unsigned char *fragment_bytes = NULL;
        size_t fragment_len = 0u;
        uint8_t role = index < 3u ? 1u : (index < 6u ? 2u : 3u);
        jint ordinal_min = index < 3u ? 0 : (index < 6u ? 3 : 6);
        jint ordinal_max = index < 3u ? 2 : (index < 6u ? 5 : 6);
        if (!js_aken_native_descriptor_read_frame(
                &plan_cursor,
                JS_AKEN_DESCRIPTOR_MAX_FRAGMENT_SIZE,
                0,
                &fragment_bytes,
                &fragment_len) ||
            !js_aken_native_descriptor_parse_fragment(
                fragment_bytes,
                fragment_len,
                role,
                ordinal_min,
                ordinal_max,
                &out_view->fragments[index],
                out_view->fragment_permutations[index])) {
            goto cleanup;
        }
    }
    if (!js_aken_native_descriptor_read_fixed(
            &plan_cursor,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE,
            &fingerprint) ||
        !js_aken_native_descriptor_cursor_finished(&plan_cursor)) {
        goto cleanup;
    }
    out_view->binding.evaluator_fingerprint = fingerprint;
    out_view->binding.evaluator_fingerprint_len = JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE;
    if (!js_aken_native_page_envelope_constant_time_equal(
            fingerprint,
            route.identity.evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            fingerprint,
            envelope->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            fingerprint,
            resolved->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_descriptor_fingerprint_matches(out_view)) {
        goto cleanup;
    }
    out_view->leaf_identity_encoding = route.identity_encoding;
    out_view->leaf_identity_encoding_len = route.identity_encoding_len;
    out_view->mesh_root = proof.mesh_root;
    out_view->leaf_digest = proof.leaf_digest;
    out_view->merkle_sibling_count = proof.merkle_sibling_count;
    for (size_t index = 0u; index < proof.merkle_sibling_count; index++) {
        out_view->merkle_siblings[index] = proof.merkle_siblings[index];
        out_view->merkle_sibling_is_left[index] = proof.merkle_sibling_is_left[index];
    }
    out_view->resource_path = route.resource_path;
    out_view->resource_path_len = route.resource_path_len;
    out_view->resource_offset = route.resource_offset;
    out_view->stored_length = route.stored_length;
    out_view->parsed = 1u;
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&route, sizeof(route));
    js_vbc4_wipe_volatile(&proof, sizeof(proof));
    if (!ok && out_view) js_aken_native_page_descriptor_view_wipe(out_view);
    return ok;
}

/*
 * AKEN v4 native terminal bound-payload opener.
 *
 * The locator/envelope layer deliberately leaves the descriptor opaque.  This
 * terminal primitive therefore consumes only a current-page evaluator binding
 * that the artifact-specific compiler generated beside that descriptor.  It
 * cross-binds every public member to the already-resolved locator result before
 * reconstructing a DEK, and it never publishes the DEK or accepts a JNI
 * generic-decode request.
 */
#define JS_AKEN_NATIVE_PAGE_CODEC_VERSION 4u
#define JS_AKEN_NATIVE_PAGE_HEADER_SIZE 202u
#define JS_AKEN_NATIVE_PAGE_GCM_TAG_SIZE 16u
#define JS_AKEN_NATIVE_PAGE_NONCE_SIZE 12u
#define JS_AKEN_NATIVE_PAGE_OFFSET_VERSION 0u
#define JS_AKEN_NATIVE_PAGE_OFFSET_KIND 1u
#define JS_AKEN_NATIVE_PAGE_OFFSET_PAGE_INDEX 2u
#define JS_AKEN_NATIVE_PAGE_OFFSET_PLAINTEXT_LENGTH 6u
#define JS_AKEN_NATIVE_PAGE_OFFSET_NONCE 10u
#define JS_AKEN_NATIVE_PAGE_OFFSET_COMMITMENT 22u
#define JS_AKEN_NATIVE_PAGE_OFFSET_IDENTITY_HASH 54u
#define JS_AKEN_NATIVE_PAGE_OFFSET_EVALUATOR_FINGERPRINT 86u
#define JS_AKEN_NATIVE_PAGE_OFFSET_CODEC_HASH 118u
#define JS_AKEN_NATIVE_PAGE_OFFSET_LAYOUT_HASH 150u
#define JS_AKEN_NATIVE_PAGE_OFFSET_LOCATOR 182u
#define JS_AKEN_NATIVE_PAGE_OFFSET_CIPHERTEXT_LENGTH 198u
#define JS_AKEN_NATIVE_PAGE_MAX_ENCODED_SIZE (16u * 1024u * 1024u)

static const unsigned char JS_AKEN_NATIVE_PAGE_AAD_DOMAIN[] = "AKEN-v4-page-aad";
static const unsigned char JS_AKEN_NATIVE_PAGE_CANONICAL_CODEC[] = "aes-256-gcm-v4";
static const unsigned char JS_AKEN_NATIVE_PAGE_LAYOUT_PREFIX[] = "aken4-frame1";

static int js_aken_native_page_open_size_add(size_t *value, size_t addend) {
    if (!value || addend > SIZE_MAX - *value) return 0;
    *value += addend;
    return 1;
}

static uint32_t js_aken_native_page_open_read_u32be(const unsigned char value[4]) {
    return ((uint32_t)value[0] << 24) |
        ((uint32_t)value[1] << 16) |
        ((uint32_t)value[2] << 8) |
        (uint32_t)value[3];
}

static void js_aken_native_page_open_write_u32be(unsigned char target[4], uint32_t value) {
    target[0] = (unsigned char)(value >> 24);
    target[1] = (unsigned char)(value >> 16);
    target[2] = (unsigned char)(value >> 8);
    target[3] = (unsigned char)value;
}

static int js_aken_native_page_open_ascii_equal(
    const unsigned char *value,
    size_t value_len,
    const unsigned char *expected,
    size_t expected_len
) {
    return value && expected && value_len == expected_len && memcmp(value, expected, value_len) == 0;
}

static int js_aken_native_page_open_sha256(
    const unsigned char *value,
    size_t value_len,
    unsigned char out_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx context;
    int ok = 0;
    if (!out_digest) return 0;
    js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    memset(&context, 0, sizeof(context));
    if (!value || value_len == 0u || value_len > (size_t)INT_MAX) goto cleanup;
    js_sha256_init(&context);
    js_sha256_update(&context, value, (int)value_len);
    js_sha256_final(&context, out_digest);
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(&context, sizeof(context));
    if (!ok) js_vbc4_wipe_volatile(out_digest, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
    return ok;
}

static int js_aken_native_page_open_layout_decimal(
    const unsigned char *value,
    size_t value_len,
    size_t minimum,
    size_t maximum,
    size_t *out_value
) {
    size_t decoded = 0u;
    if (!value || !out_value || value_len == 0u || (value_len > 1u && value[0] == (unsigned char)'0')) return 0;
    for (size_t index = 0u; index < value_len; index++) {
        unsigned char character = value[index];
        unsigned int digit = 0u;
        if (character < (unsigned char)'0' || character > (unsigned char)'9') return 0;
        digit = (unsigned int)(character - (unsigned char)'0');
        if (decoded > (maximum - (size_t)digit) / 10u) return 0;
        decoded = decoded * 10u + (size_t)digit;
    }
    if (decoded < minimum || decoded > maximum || (decoded & 3u) != 0u) return 0;
    *out_value = decoded;
    return 1;
}

static int js_aken_native_page_open_base64url_value(unsigned char character, unsigned int *out_value) {
    unsigned int value = 0u;
    if (!out_value) return 0;
    if (character >= (unsigned char)'A' && character <= (unsigned char)'Z') {
        value = (unsigned int)(character - (unsigned char)'A');
    } else if (character >= (unsigned char)'a' && character <= (unsigned char)'z') {
        value = 26u + (unsigned int)(character - (unsigned char)'a');
    } else if (character >= (unsigned char)'0' && character <= (unsigned char)'9') {
        value = 52u + (unsigned int)(character - (unsigned char)'0');
    } else if (character == (unsigned char)'-') {
        value = 62u;
    } else if (character == (unsigned char)'_') {
        value = 63u;
    } else {
        return 0;
    }
    *out_value = value;
    return 1;
}

static int js_aken_native_page_open_layout_parse(
    const unsigned char *variant,
    size_t variant_len,
    size_t *out_prefix_len,
    size_t *out_suffix_len,
    int *out_header_after_body
) {
    const unsigned char *parts[6] = {0};
    size_t lengths[6] = {0};
    size_t part_count = 0u;
    size_t start = 0u;
    size_t prefix_len = 0u;
    size_t suffix_len = 0u;
    int header_after_body = 0;
    int ok = 0;
    if (!variant || !out_prefix_len || !out_suffix_len || !out_header_after_body ||
        variant_len == 0u || variant_len > JS_AKEN_EVALUATOR_MAX_FRAGMENT_BYTES) {
        goto cleanup;
    }
    for (size_t index = 0u; index <= variant_len; index++) {
        if (index == variant_len || variant[index] == (unsigned char)':') {
            if (part_count >= 6u || index < start) goto cleanup;
            parts[part_count] = variant + start;
            lengths[part_count] = index - start;
            part_count++;
            start = index + 1u;
        }
    }
    if (part_count != 6u ||
        !js_aken_native_page_open_ascii_equal(
            parts[0],
            lengths[0],
            JS_AKEN_NATIVE_PAGE_LAYOUT_PREFIX,
            sizeof(JS_AKEN_NATIVE_PAGE_LAYOUT_PREFIX) - 1u) ||
        lengths[1] == 0u || lengths[1] > 32u ||
        !((parts[1][0] >= (unsigned char)'a' && parts[1][0] <= (unsigned char)'z') ||
            (parts[1][0] >= (unsigned char)'0' && parts[1][0] <= (unsigned char)'9')) ||
        !js_aken_native_page_open_layout_decimal(parts[2], lengths[2], 12u, 60u, &prefix_len) ||
        !js_aken_native_page_open_layout_decimal(parts[3], lengths[3], 8u, 40u, &suffix_len)) {
        goto cleanup;
    }
    for (size_t index = 1u; index < lengths[1]; index++) {
        unsigned char character = parts[1][index];
        if (!((character >= (unsigned char)'a' && character <= (unsigned char)'z') ||
            (character >= (unsigned char)'0' && character <= (unsigned char)'9') ||
            character == (unsigned char)'.' || character == (unsigned char)'_' || character == (unsigned char)'-')) {
            goto cleanup;
        }
    }
    if (js_aken_native_page_open_ascii_equal(parts[4], lengths[4], (const unsigned char *)"head", 4u)) {
        header_after_body = 0;
    } else if (js_aken_native_page_open_ascii_equal(parts[4], lengths[4], (const unsigned char *)"tail", 4u)) {
        header_after_body = 1;
    } else {
        goto cleanup;
    }
    if (lengths[5] != 11u) goto cleanup;
    for (size_t index = 0u; index < lengths[5]; index++) {
        unsigned int marker_value = 0u;
        if (!js_aken_native_page_open_base64url_value(parts[5][index], &marker_value) ||
            (index + 1u == lengths[5] && (marker_value & 0x03u) != 0u)) {
            goto cleanup;
        }
    }
    *out_prefix_len = prefix_len;
    *out_suffix_len = suffix_len;
    *out_header_after_body = header_after_body;
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(parts, sizeof(parts));
    js_vbc4_wipe_volatile(lengths, sizeof(lengths));
    return ok;
}

static int js_aken_native_page_open_write_framed(
    unsigned char *target,
    size_t target_len,
    size_t *offset,
    const unsigned char *value,
    size_t value_len
) {
    size_t next = 0u;
    if (!target || !offset || (value_len != 0u && !value) || value_len > (size_t)UINT32_MAX ||
        *offset > target_len || !js_aken_native_page_open_size_add(&next, *offset) ||
        !js_aken_native_page_open_size_add(&next, 4u) ||
        !js_aken_native_page_open_size_add(&next, value_len) || next > target_len) {
        return 0;
    }
    js_aken_native_page_open_write_u32be(target + *offset, (uint32_t)value_len);
    *offset += 4u;
    if (value_len != 0u) memcpy(target + *offset, value, value_len);
    *offset += value_len;
    return 1;
}

static int js_aken_native_page_open_build_aad(
    const js_aken_evaluator_binding *binding,
    const unsigned char header[JS_AKEN_NATIVE_PAGE_HEADER_SIZE],
    const unsigned char *prefix,
    size_t prefix_len,
    const unsigned char *suffix,
    size_t suffix_len,
    unsigned char **out_aad,
    size_t *out_aad_len
) {
    size_t total = 0u;
    size_t offset = 0u;
    unsigned char *aad = NULL;
    int ok = 0;
    if (!binding || !header || (prefix_len != 0u && !prefix) || (suffix_len != 0u && !suffix) ||
        !out_aad || !out_aad_len) {
        goto cleanup;
    }
    *out_aad = NULL;
    *out_aad_len = 0u;
    if (!js_aken_native_page_open_size_add(&total, sizeof(JS_AKEN_NATIVE_PAGE_AAD_DOMAIN) - 1u) ||
        !js_aken_native_page_open_size_add(&total, binding->artifact_commitment_len) ||
        !js_aken_native_page_open_size_add(&total, 4u + binding->logical_identity_len) ||
        !js_aken_native_page_open_size_add(&total, 4u) ||
        !js_aken_native_page_open_size_add(&total, 1u) ||
        !js_aken_native_page_open_size_add(&total, binding->evaluator_fingerprint_len) ||
        !js_aken_native_page_open_size_add(&total, 4u + binding->codec_variant_len) ||
        !js_aken_native_page_open_size_add(&total, 4u + binding->layout_variant_len) ||
        !js_aken_native_page_open_size_add(&total, binding->locator_token_len) ||
        !js_aken_native_page_open_size_add(&total, 4u + JS_AKEN_NATIVE_PAGE_HEADER_SIZE) ||
        !js_aken_native_page_open_size_add(&total, 4u + prefix_len) ||
        !js_aken_native_page_open_size_add(&total, 4u + suffix_len) ||
        total == 0u || total > JS_AKEN_NATIVE_PAGE_MAX_ENCODED_SIZE) {
        goto cleanup;
    }
    aad = (unsigned char *)malloc(total);
    if (!aad) goto cleanup;
    memcpy(aad + offset, JS_AKEN_NATIVE_PAGE_AAD_DOMAIN, sizeof(JS_AKEN_NATIVE_PAGE_AAD_DOMAIN) - 1u);
    offset += sizeof(JS_AKEN_NATIVE_PAGE_AAD_DOMAIN) - 1u;
    memcpy(aad + offset, binding->artifact_commitment, binding->artifact_commitment_len);
    offset += binding->artifact_commitment_len;
    if (!js_aken_native_page_open_write_framed(aad, total, &offset, binding->logical_identity, binding->logical_identity_len)) {
        goto cleanup;
    }
    if (offset > total || total - offset < 5u) goto cleanup;
    js_aken_native_page_open_write_u32be(aad + offset, (uint32_t)binding->page_index);
    offset += 4u;
    aad[offset++] = binding->kind_id;
    memcpy(aad + offset, binding->evaluator_fingerprint, binding->evaluator_fingerprint_len);
    offset += binding->evaluator_fingerprint_len;
    if (!js_aken_native_page_open_write_framed(aad, total, &offset, binding->codec_variant, binding->codec_variant_len) ||
        !js_aken_native_page_open_write_framed(aad, total, &offset, binding->layout_variant, binding->layout_variant_len)) {
        goto cleanup;
    }
    if (offset > total || binding->locator_token_len > total - offset) goto cleanup;
    memcpy(aad + offset, binding->locator_token, binding->locator_token_len);
    offset += binding->locator_token_len;
    if (!js_aken_native_page_open_write_framed(aad, total, &offset, header, JS_AKEN_NATIVE_PAGE_HEADER_SIZE) ||
        !js_aken_native_page_open_write_framed(aad, total, &offset, prefix, prefix_len) ||
        !js_aken_native_page_open_write_framed(aad, total, &offset, suffix, suffix_len) ||
        offset != total) {
        goto cleanup;
    }
    *out_aad = aad;
    *out_aad_len = total;
    aad = NULL;
    ok = 1;
cleanup:
    if (aad) {
        js_vbc4_wipe_volatile(aad, total);
        free(aad);
    }
    return ok;
}

static int js_aken_native_page_open_bindings_match(
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved,
    const js_aken_evaluator_binding *binding
) {
    if (!js_aken_native_page_request_is_valid(request) ||
        !js_aken_native_page_envelope_record_is_well_formed(envelope, 1) ||
        !js_aken_native_page_resolved_descriptor_is_well_formed(resolved) ||
        !js_aken_evaluator_binding_is_valid(binding) ||
        !js_aken_native_page_envelope_verify_resolved_bindings(envelope, resolved)) {
        return 0;
    }
    return binding->kind_id == request->resource_kind &&
        binding->kind_id == envelope->resource_kind &&
        binding->kind_id == resolved->resource_kind &&
        binding->page_index == request->page_index &&
        binding->page_index == envelope->page_index &&
        binding->page_index == resolved->page_index &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->encoded_handle,
            request->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->encoded_handle,
            envelope->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->encoded_handle,
            resolved->encoded_handle,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->locator_token,
            envelope->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->locator_token,
            resolved->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->evaluator_fingerprint,
            envelope->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->evaluator_fingerprint,
            resolved->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->artifact_commitment,
            envelope->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) &&
        js_aken_native_page_envelope_constant_time_equal(
            binding->artifact_commitment,
            resolved->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE);
}

JS_HIDDEN void js_aken_native_opened_page_wipe(js_aken_native_opened_page *page) {
    if (!page) return;
    if (page->bytes) {
        js_vbc4_wipe_volatile(page->bytes, page->length);
        free(page->bytes);
    }
    js_vbc4_wipe_volatile(page, sizeof(*page));
}

JS_HIDDEN int js_aken_native_page_open_bound_payload(
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved,
    const js_aken_evaluator_binding *binding,
    const js_aken_evaluator_fragment *fragments,
    size_t fragment_count,
    const unsigned char *encoded_payload,
    size_t encoded_payload_len,
    js_aken_native_opened_page *out_page
) {
    const unsigned char *header = NULL;
    const unsigned char *body = NULL;
    const unsigned char *prefix = NULL;
    const unsigned char *suffix = NULL;
    const unsigned char *nonce = NULL;
    size_t prefix_len = 0u;
    size_t suffix_len = 0u;
    size_t header_offset = 0u;
    size_t body_offset = 0u;
    size_t expected_total = 0u;
    size_t declared_plain_len = 0u;
    size_t declared_body_len = 0u;
    int header_after_body = 0;
    unsigned char identity_hash[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char codec_hash[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char layout_hash[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char dek[JS_AKEN_EVALUATOR_STATE_WIDTH] = {0};
    unsigned char *aad = NULL;
    size_t aad_len = 0u;
    unsigned char *plain = NULL;
    int ok = 0;
    if (!out_page) goto cleanup;
    js_vbc4_wipe_volatile(out_page, sizeof(*out_page));
    if (!encoded_payload || encoded_payload_len == 0u || encoded_payload_len > JS_AKEN_NATIVE_PAGE_MAX_ENCODED_SIZE ||
        !js_aken_native_page_open_bindings_match(request, envelope, resolved, binding) ||
        !js_aken_native_page_open_ascii_equal(
            binding->codec_variant,
            binding->codec_variant_len,
            JS_AKEN_NATIVE_PAGE_CANONICAL_CODEC,
            sizeof(JS_AKEN_NATIVE_PAGE_CANONICAL_CODEC) - 1u) ||
        !js_aken_native_page_open_layout_parse(
            binding->layout_variant,
            binding->layout_variant_len,
            &prefix_len,
            &suffix_len,
            &header_after_body)) {
        goto cleanup;
    }
    expected_total = prefix_len;
    if (!js_aken_native_page_open_size_add(&expected_total, JS_AKEN_NATIVE_PAGE_HEADER_SIZE) ||
        !js_aken_native_page_open_size_add(&expected_total, JS_AKEN_NATIVE_PAGE_GCM_TAG_SIZE) ||
        !js_aken_native_page_open_size_add(&expected_total, suffix_len) ||
        encoded_payload_len < expected_total) {
        goto cleanup;
    }
    if (header_after_body) {
        header_offset = encoded_payload_len - suffix_len - JS_AKEN_NATIVE_PAGE_HEADER_SIZE;
        body_offset = prefix_len;
    } else {
        header_offset = prefix_len;
        body_offset = prefix_len + JS_AKEN_NATIVE_PAGE_HEADER_SIZE;
    }
    if (header_offset > encoded_payload_len ||
        JS_AKEN_NATIVE_PAGE_HEADER_SIZE > encoded_payload_len - header_offset ||
        body_offset > encoded_payload_len) {
        goto cleanup;
    }
    header = encoded_payload + header_offset;
    declared_plain_len = (size_t)js_aken_native_page_open_read_u32be(
        header + JS_AKEN_NATIVE_PAGE_OFFSET_PLAINTEXT_LENGTH);
    declared_body_len = (size_t)js_aken_native_page_open_read_u32be(
        header + JS_AKEN_NATIVE_PAGE_OFFSET_CIPHERTEXT_LENGTH);
    if (declared_plain_len == 0u || declared_plain_len > JS_AKEN_NATIVE_PAGE_MAX_ENCODED_SIZE ||
        declared_plain_len > SIZE_MAX - JS_AKEN_NATIVE_PAGE_GCM_TAG_SIZE ||
        declared_body_len != declared_plain_len + JS_AKEN_NATIVE_PAGE_GCM_TAG_SIZE) {
        goto cleanup;
    }
    expected_total = prefix_len;
    if (!js_aken_native_page_open_size_add(&expected_total, JS_AKEN_NATIVE_PAGE_HEADER_SIZE) ||
        !js_aken_native_page_open_size_add(&expected_total, declared_body_len) ||
        !js_aken_native_page_open_size_add(&expected_total, suffix_len) ||
        expected_total != encoded_payload_len ||
        declared_body_len > encoded_payload_len - body_offset) {
        goto cleanup;
    }
    if (header_after_body && header_offset != body_offset + declared_body_len) goto cleanup;
    if (!header_after_body && header_offset + JS_AKEN_NATIVE_PAGE_HEADER_SIZE != body_offset) goto cleanup;
    prefix = encoded_payload;
    suffix = encoded_payload + encoded_payload_len - suffix_len;
    body = encoded_payload + body_offset;
    nonce = header + JS_AKEN_NATIVE_PAGE_OFFSET_NONCE;
    if ((header[JS_AKEN_NATIVE_PAGE_OFFSET_VERSION] & 0xFFu) != JS_AKEN_NATIVE_PAGE_CODEC_VERSION ||
        header[JS_AKEN_NATIVE_PAGE_OFFSET_KIND] != binding->kind_id ||
        (jint)js_aken_native_page_open_read_u32be(header + JS_AKEN_NATIVE_PAGE_OFFSET_PAGE_INDEX) != binding->page_index ||
        !js_aken_native_page_open_sha256(binding->logical_identity, binding->logical_identity_len, identity_hash) ||
        !js_aken_native_page_open_sha256(
            JS_AKEN_NATIVE_PAGE_CANONICAL_CODEC,
            sizeof(JS_AKEN_NATIVE_PAGE_CANONICAL_CODEC) - 1u,
            codec_hash) ||
        !js_aken_native_page_open_sha256(binding->layout_variant, binding->layout_variant_len, layout_hash) ||
        !js_aken_native_page_envelope_constant_time_equal(
            header + JS_AKEN_NATIVE_PAGE_OFFSET_COMMITMENT,
            binding->artifact_commitment,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            header + JS_AKEN_NATIVE_PAGE_OFFSET_IDENTITY_HASH,
            identity_hash,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            header + JS_AKEN_NATIVE_PAGE_OFFSET_EVALUATOR_FINGERPRINT,
            binding->evaluator_fingerprint,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            header + JS_AKEN_NATIVE_PAGE_OFFSET_CODEC_HASH,
            codec_hash,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            header + JS_AKEN_NATIVE_PAGE_OFFSET_LAYOUT_HASH,
            layout_hash,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !js_aken_native_page_envelope_constant_time_equal(
            header + JS_AKEN_NATIVE_PAGE_OFFSET_LOCATOR,
            binding->locator_token,
            JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE)) {
        goto cleanup;
    }
    if (!js_aken_native_page_open_build_aad(
            binding,
            header,
            prefix,
            prefix_len,
            suffix,
            suffix_len,
            &aad,
            &aad_len) ||
        !js_aken_evaluator_recover_dek(binding, fragments, fragment_count, dek)) {
        goto cleanup;
    }
    plain = (unsigned char *)malloc(declared_plain_len);
    if (!plain ||
        !js_aes_gcm_decrypt(
            dek,
            sizeof(dek),
            nonce,
            aad,
            aad_len,
            body,
            declared_body_len,
            plain)) {
        goto cleanup;
    }
    out_page->bytes = plain;
    out_page->length = declared_plain_len;
    plain = NULL;
    ok = 1;
cleanup:
    if (plain) {
        js_vbc4_wipe_volatile(plain, declared_plain_len);
        free(plain);
    }
    if (aad) {
        js_vbc4_wipe_volatile(aad, aad_len);
        free(aad);
    }
    js_vbc4_wipe_volatile(identity_hash, sizeof(identity_hash));
    js_vbc4_wipe_volatile(codec_hash, sizeof(codec_hash));
    js_vbc4_wipe_volatile(layout_hash, sizeof(layout_hash));
    js_vbc4_wipe_volatile(dek, sizeof(dek));
    if (!ok && out_page) js_vbc4_wipe_volatile(out_page, sizeof(*out_page));
    return ok;
}

/*
 * Loads and copies only the exact current encrypted page slice named by a
 * parsed AKEN route. The path, offset, and length originate exclusively from
 * js_aken_native_page_descriptor_parse_current(); this helper deliberately
 * bypasses legacy alias, commitment, and generic decode paths.
 */
static int js_aken_native_page_load_current_route_slice(
    JNIEnv *env,
    jclass helper_cls,
    const js_aken_native_page_descriptor_view *view,
    unsigned char **out_payload,
    size_t *out_payload_len
) {
    char resource_path[JS_AKEN_DESCRIPTOR_MAX_RESOURCE_PATH_SIZE + 1u];
    jstring resource_path_j = NULL;
    js_vm_loaded_resource loaded;
    unsigned char *payload = NULL;
    jsize raw_length = 0;
    size_t offset = 0u;
    size_t stored_length = 0u;
    int ok = 0;
    memset(&loaded, 0, sizeof(loaded));
    if (!out_payload || !out_payload_len) goto cleanup;
    *out_payload = NULL;
    *out_payload_len = 0u;
    if (!env || !helper_cls || !view || view->parsed != 1u ||
        !view->resource_path || view->resource_path_len == 0u ||
        view->resource_path_len > JS_AKEN_DESCRIPTOR_MAX_RESOURCE_PATH_SIZE ||
        view->stored_length == 0u ||
        view->stored_length > JS_AKEN_NATIVE_PAGE_MAX_ENCODED_SIZE) {
        goto cleanup;
    }
    memcpy(resource_path, view->resource_path, view->resource_path_len);
    resource_path[view->resource_path_len] = '\0';
    resource_path_j = (*env)->NewStringUTF(env, resource_path);
    js_vbc4_wipe_volatile(resource_path, sizeof(resource_path));
    if (!resource_path_j || (*env)->ExceptionCheck(env)) goto cleanup;
    loaded = js_vm_load_resource_bytes_with_loader(env, helper_cls, resource_path_j);
    if (!loaded.bytes || (*env)->ExceptionCheck(env)) goto cleanup;
    raw_length = (*env)->GetArrayLength(env, loaded.bytes);
    if ((*env)->ExceptionCheck(env) || raw_length <= 0) goto cleanup;
    offset = (size_t)view->resource_offset;
    stored_length = (size_t)view->stored_length;
    if (offset > (size_t)raw_length || stored_length > (size_t)raw_length - offset) goto cleanup;
    payload = (unsigned char *)malloc(stored_length);
    if (!payload) goto cleanup;
    (*env)->GetByteArrayRegion(
        env,
        loaded.bytes,
        (jsize)offset,
        (jsize)stored_length,
        (jbyte *)payload);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    *out_payload = payload;
    *out_payload_len = stored_length;
    payload = NULL;
    ok = 1;
cleanup:
    if (payload) {
        js_vbc4_wipe_volatile(payload, stored_length);
        free(payload);
    }
    if (loaded.bytes) (*env)->DeleteLocalRef(env, loaded.bytes);
    if (loaded.loader) (*env)->DeleteLocalRef(env, loaded.loader);
    if (resource_path_j) (*env)->DeleteLocalRef(env, resource_path_j);
    js_vbc4_wipe_volatile(resource_path, sizeof(resource_path));
    if (!ok && out_payload && out_payload_len) {
        *out_payload = NULL;
        *out_payload_len = 0u;
    }
    return ok;
}

JS_HIDDEN int js_aken_native_page_open_current_view_payload(
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved,
    const js_aken_native_page_descriptor_view *view,
    const unsigned char *encoded_payload,
    size_t encoded_payload_len,
    js_aken_native_opened_page *out_page
) {
    int ok = 0;
    if (!out_page) return 0;
    js_vbc4_wipe_volatile(out_page, sizeof(*out_page));
    if (!view || view->parsed != 1u ||
        !js_aken_native_page_descriptor_verify_payload_mesh(
            view, encoded_payload, encoded_payload_len)) {
        return 0;
    }
    ok = js_aken_native_page_open_bound_payload(
        request,
        envelope,
        resolved,
        &view->binding,
        view->fragments,
        JS_AKEN_EVALUATOR_FRAGMENT_COUNT,
        encoded_payload,
        encoded_payload_len,
        out_page);
    if (!ok) js_vbc4_wipe_volatile(out_page, sizeof(*out_page));
    return ok;
}

static jobject JNICALL jsw_a0(JNIEnv *env, jclass cls, jlong entry_token, jbyteArray encoded_handle, jint page_index, jbyteArray call_site_proof, jobjectArray args) {
    unsigned char native_handle[JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE] = {0};
    unsigned char native_call_site_proof[JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE] = {0};
    js_aken_native_page_request request;
    js_aken_native_page_locator_record record;
    js_aken_native_page_envelope envelope;
    js_aken_native_page_resolved_descriptor resolved;
    js_aken_native_page_descriptor_view descriptor_view;
    js_aken_native_opened_page opened_page;
    unsigned char *encoded_payload = NULL;
    size_t encoded_payload_len = 0u;
    jsize proof_length = 0;
    int protected_runtime_entered = 0;
    (void)args;
    memset(&request, 0, sizeof(request));
    memset(&record, 0, sizeof(record));
    memset(&envelope, 0, sizeof(envelope));
    memset(&resolved, 0, sizeof(resolved));
    memset(&descriptor_view, 0, sizeof(descriptor_view));
    memset(&opened_page, 0, sizeof(opened_page));
    if (!js_vm_sensitive_path_guard(env, (const void*)jsw_a0, 0)) goto cleanup;
    if (!js_protected_runtime_enter(env)) goto cleanup;
    protected_runtime_entered = 1;
    if (!js_aken_bridge_request_shape_is_valid(env, encoded_handle, page_index, call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN VM page route is invalid");
        goto cleanup;
    }
    proof_length = (*env)->GetArrayLength(env, call_site_proof);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    if (proof_length <= 0 || (size_t)proof_length > sizeof(native_call_site_proof)) {
        js_aken_bridge_unavailable(env, "AKEN VM page route is invalid");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(
        env,
        encoded_handle,
        0,
        (jsize)sizeof(native_handle),
        (jbyte *)native_handle);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->GetByteArrayRegion(
        env,
        call_site_proof,
        0,
        proof_length,
        (jbyte *)native_call_site_proof);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    request.entry_token = (uint64_t)entry_token;
    request.resource_kind = JS_AKEN_NATIVE_PAGE_RESOURCE_KIND_VBC4_METHOD;
    request.page_index = page_index;
    request.encoded_handle = native_handle;
    request.encoded_handle_len = sizeof(native_handle);
    request.raw_call_site_proof = native_call_site_proof;
    request.raw_call_site_proof_len = (size_t)proof_length;
    if (!js_aken_native_page_locator_lookup(&request, &record)) {
        js_aken_bridge_unavailable(env, "AKEN VM page route is unavailable");
        goto cleanup;
    }
    if (!js_aken_native_page_envelope_parse(
            record.native_envelope,
            record.native_envelope_len,
            &request,
            &envelope) ||
        !js_aken_native_page_locator_resolve(&record, &envelope, &resolved) ||
        !js_aken_native_page_descriptor_parse_current(
            &request,
            &envelope,
            &resolved,
            &descriptor_view)) {
        js_aken_bridge_unavailable(env, "AKEN VM page route is invalid");
        goto cleanup;
    }
    if (!js_aken_native_page_load_current_route_slice(
            env,
            cls,
            &descriptor_view,
            &encoded_payload,
            &encoded_payload_len) ||
        !js_aken_native_page_open_current_view_payload(
            &request,
            &envelope,
            &resolved,
            &descriptor_view,
            encoded_payload,
            encoded_payload_len,
            &opened_page)) {
        js_aken_bridge_unavailable(env, "AKEN VM page authentication failed");
        goto cleanup;
    }
    js_aken_native_opened_page_wipe(&opened_page);
    js_aken_bridge_unavailable(env, "AKEN VM page executor is unavailable");
cleanup:
    js_aken_native_opened_page_wipe(&opened_page);
    if (encoded_payload) {
        js_vbc4_wipe_volatile(encoded_payload, encoded_payload_len);
        free(encoded_payload);
    }
    js_aken_native_page_descriptor_view_wipe(&descriptor_view);
    js_vbc4_wipe_volatile(&resolved, sizeof(resolved));
    js_aken_native_page_envelope_wipe(&envelope);
    js_aken_native_page_locator_record_wipe(&record);
    js_vbc4_wipe_volatile(&request, sizeof(request));
    js_vbc4_wipe_volatile(native_handle, sizeof(native_handle));
    js_vbc4_wipe_volatile(native_call_site_proof, sizeof(native_call_site_proof));
    if (protected_runtime_entered) (void)js_protected_runtime_leave(env);
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
        {js_native_name("Execute", "AkenVm", "Page"), "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;", (void*)jsw_a0},
        {js_native_name("Decode", "AkenString", "Page"), "([BI[B)[B", (void*)jsw_a1},
        {js_native_name("Read", "AkenClass", "Page"), "([BI[B)[B", (void*)jsw_a2},
        {js_native_name("Map", "AkenNative", "Chunk"), "([BI[B)[B", (void*)jsw_a3},
    };
    if (!js_register_native_group(env, js_helper_owner("Jni", "Micro", "kernel", "Helper"), jni_microkernel_methods, (int)(sizeof(jni_microkernel_methods) / sizeof(jni_microkernel_methods[0])), 1)) return 0;
    return js_register_optional_natives(env);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    if (reserved == JS_SHELL_MANUAL_MAP_RESERVED) js_jni_runtime_manual_mapped_shell = 1;
    if (!js_protected_section_enter()) {
        JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE("protected-enter");
        return JNI_ERR;
    }
    js_native_anti_dump_harden();
    js_vm_cache_lock_init();
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE("get-env");
        (void)js_protected_section_leave();
        return JNI_ERR;
    }
    if (!js_jni_cache_init(env)) {
        JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE("cache-init");
        (void)js_protected_section_leave();
        return JNI_ERR;
    }
    int ok = 1;
    if (!js_jni_runtime_manual_mapped_shell) {
        ok = js_register_all_natives(env);
        if (!ok) JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE("register-all");
        if (ok && (*env)->ExceptionCheck(env)) {
            JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE("pending-exception");
            js_vm_clear_exception(env);
            ok = 0;
        }
    }
    if (ok) js_vm_mark_hot_integrity_baseline_clean();
    if (!ok) js_jni_cache_destroy(env);
    if (!js_protected_section_leave()) {
        JS_AKEN_JNI_FIXTURE_ONLOAD_FAILURE("protected-leave");
        ok = 0;
    }
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
