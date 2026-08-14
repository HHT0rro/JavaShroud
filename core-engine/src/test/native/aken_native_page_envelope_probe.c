#include "js_jni_runtime.h"
#include "js_crypto.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define TEST_CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "AKEN native envelope probe failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
        return 0; \
    } \
} while (0)

typedef struct {
    uint8_t form;
    uint64_t entry_token;
    uint8_t resource_kind;
    jint page_index;
    unsigned char encoded_handle[JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE];
    unsigned char locator_token[JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE];
    unsigned char evaluator_fingerprint[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char artifact_commitment[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    const unsigned char *descriptor;
    size_t descriptor_len;
    const unsigned char *route;
    size_t route_len;
    const unsigned char *raw_call_site_proof;
    size_t raw_call_site_proof_len;
} test_page_fixture;

static const unsigned char TEST_DESCRIPTOR_DOMAIN[] = "AKEN-v4-native-page-envelope-descriptor-v1";
static const unsigned char TEST_CALL_SITE_DOMAIN[] = "AKEN-v4-native-page-envelope-call-site-v1";
static const unsigned char TEST_ROUTE_DOMAIN[] = "AKEN-v4-native-page-envelope-route-v1";
static const unsigned char TEST_ENVELOPE_DOMAIN[] = "AKEN-v4-native-page-envelope-v1";

static void test_write_u32be(unsigned char **cursor, uint32_t value) {
    (*cursor)[0] = (unsigned char)(value >> 24);
    (*cursor)[1] = (unsigned char)(value >> 16);
    (*cursor)[2] = (unsigned char)(value >> 8);
    (*cursor)[3] = (unsigned char)value;
    *cursor += 4;
}

static void test_write_u64be(unsigned char **cursor, uint64_t value) {
    (*cursor)[0] = (unsigned char)(value >> 56);
    (*cursor)[1] = (unsigned char)(value >> 48);
    (*cursor)[2] = (unsigned char)(value >> 40);
    (*cursor)[3] = (unsigned char)(value >> 32);
    (*cursor)[4] = (unsigned char)(value >> 24);
    (*cursor)[5] = (unsigned char)(value >> 16);
    (*cursor)[6] = (unsigned char)(value >> 8);
    (*cursor)[7] = (unsigned char)value;
    *cursor += 8;
}

static void test_update_u32be(js_sha256_ctx *ctx, uint32_t value) {
    unsigned char bytes[4];
    unsigned char *cursor = bytes;
    test_write_u32be(&cursor, value);
    js_sha256_update(ctx, bytes, (int)sizeof(bytes));
    js_vbc4_wipe_volatile(bytes, sizeof(bytes));
}

static void test_update_u64be(js_sha256_ctx *ctx, uint64_t value) {
    unsigned char bytes[8];
    unsigned char *cursor = bytes;
    test_write_u64be(&cursor, value);
    js_sha256_update(ctx, bytes, (int)sizeof(bytes));
    js_vbc4_wipe_volatile(bytes, sizeof(bytes));
}

static int test_update_framed(js_sha256_ctx *ctx, const unsigned char *value, size_t value_len) {
    if (!ctx || !value || value_len == 0u || value_len > (size_t)INT_MAX) return 0;
    test_update_u32be(ctx, (uint32_t)value_len);
    js_sha256_update(ctx, value, (int)value_len);
    return 1;
}

static int test_digest_one_framed(
    const unsigned char *domain,
    size_t domain_len,
    const unsigned char *value,
    size_t value_len,
    unsigned char out[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx ctx;
    if (!domain || domain_len == 0u || domain_len > (size_t)INT_MAX || !value || value_len == 0u || !out) return 0;
    memset(&ctx, 0, sizeof(ctx));
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, domain, (int)domain_len);
    if (!test_update_framed(&ctx, value, value_len)) {
        js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
        return 0;
    }
    js_sha256_final(&ctx, out);
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    return 1;
}

static int test_digest_route(
    const unsigned char *route,
    size_t route_len,
    const unsigned char locator[JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE],
    unsigned char out[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx ctx;
    if (!route || route_len == 0u || !locator || !out) return 0;
    memset(&ctx, 0, sizeof(ctx));
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, TEST_ROUTE_DOMAIN, (int)(sizeof(TEST_ROUTE_DOMAIN) - 1u));
    if (!test_update_framed(&ctx, route, route_len) ||
        !test_update_framed(&ctx, locator, JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE)) {
        js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
        return 0;
    }
    js_sha256_final(&ctx, out);
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    return 1;
}

static int test_digest_envelope(
    const test_page_fixture *fixture,
    const unsigned char descriptor_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE],
    const unsigned char call_site_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE],
    const unsigned char route_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE],
    unsigned char out[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE]
) {
    js_sha256_ctx ctx;
    if (!fixture || !descriptor_binding || !call_site_binding || !route_binding || !out) return 0;
    memset(&ctx, 0, sizeof(ctx));
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, TEST_ENVELOPE_DOMAIN, (int)(sizeof(TEST_ENVELOPE_DOMAIN) - 1u));
    js_sha256_update(&ctx, &fixture->form, 1);
    test_update_u64be(&ctx, fixture->entry_token);
    js_sha256_update(&ctx, &fixture->resource_kind, 1);
    test_update_u32be(&ctx, (uint32_t)fixture->page_index);
    if (!test_update_framed(&ctx, fixture->encoded_handle, sizeof(fixture->encoded_handle)) ||
        !test_update_framed(&ctx, fixture->locator_token, sizeof(fixture->locator_token)) ||
        !test_update_framed(&ctx, fixture->evaluator_fingerprint, sizeof(fixture->evaluator_fingerprint)) ||
        !test_update_framed(&ctx, fixture->artifact_commitment, sizeof(fixture->artifact_commitment)) ||
        !test_update_framed(&ctx, descriptor_binding, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !test_update_framed(&ctx, call_site_binding, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        !test_update_framed(&ctx, route_binding, JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE) ||
        (fixture->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR &&
            !test_update_framed(&ctx, fixture->descriptor, fixture->descriptor_len))) {
        js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
        return 0;
    }
    js_sha256_final(&ctx, out);
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    return 1;
}

static size_t test_build_envelope(unsigned char *out, size_t out_capacity, const test_page_fixture *fixture) {
    unsigned char descriptor_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char call_site_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char route_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char envelope_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE] = {0};
    unsigned char *cursor = out;
    size_t required_size;
    int ok = 0;
    if (!out || !fixture || !fixture->descriptor || fixture->descriptor_len == 0u || !fixture->route ||
        fixture->route_len == 0u || !fixture->raw_call_site_proof || fixture->raw_call_site_proof_len == 0u) {
        goto cleanup;
    }
    required_size = JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE;
    if (fixture->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR) {
        required_size += 4u + fixture->descriptor_len;
    } else if (fixture->form != JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_COMPACT_LOCATOR) {
        goto cleanup;
    }
    if (required_size > out_capacity || required_size > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE) goto cleanup;
    if (!test_digest_one_framed(
            TEST_DESCRIPTOR_DOMAIN,
            sizeof(TEST_DESCRIPTOR_DOMAIN) - 1u,
            fixture->descriptor,
            fixture->descriptor_len,
            descriptor_binding) ||
        !test_digest_one_framed(
            TEST_CALL_SITE_DOMAIN,
            sizeof(TEST_CALL_SITE_DOMAIN) - 1u,
            fixture->raw_call_site_proof,
            fixture->raw_call_site_proof_len,
            call_site_binding) ||
        !test_digest_route(fixture->route, fixture->route_len, fixture->locator_token, route_binding) ||
        !test_digest_envelope(fixture, descriptor_binding, call_site_binding, route_binding, envelope_binding)) {
        goto cleanup;
    }
    *cursor++ = JS_AKEN_NATIVE_PAGE_ENVELOPE_VERSION;
    *cursor++ = fixture->form;
    test_write_u64be(&cursor, fixture->entry_token);
    *cursor++ = fixture->resource_kind;
    test_write_u32be(&cursor, (uint32_t)fixture->page_index);
    memcpy(cursor, fixture->encoded_handle, sizeof(fixture->encoded_handle));
    cursor += sizeof(fixture->encoded_handle);
    memcpy(cursor, fixture->locator_token, sizeof(fixture->locator_token));
    cursor += sizeof(fixture->locator_token);
    memcpy(cursor, fixture->evaluator_fingerprint, sizeof(fixture->evaluator_fingerprint));
    cursor += sizeof(fixture->evaluator_fingerprint);
    memcpy(cursor, fixture->artifact_commitment, sizeof(fixture->artifact_commitment));
    cursor += sizeof(fixture->artifact_commitment);
    memcpy(cursor, descriptor_binding, sizeof(descriptor_binding));
    cursor += sizeof(descriptor_binding);
    memcpy(cursor, call_site_binding, sizeof(call_site_binding));
    cursor += sizeof(call_site_binding);
    memcpy(cursor, route_binding, sizeof(route_binding));
    cursor += sizeof(route_binding);
    if (fixture->form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR) {
        test_write_u32be(&cursor, (uint32_t)fixture->descriptor_len);
        memcpy(cursor, fixture->descriptor, fixture->descriptor_len);
        cursor += fixture->descriptor_len;
    }
    memcpy(cursor, envelope_binding, sizeof(envelope_binding));
    cursor += sizeof(envelope_binding);
    if ((size_t)(cursor - out) != required_size) goto cleanup;
    ok = 1;
cleanup:
    js_vbc4_wipe_volatile(descriptor_binding, sizeof(descriptor_binding));
    js_vbc4_wipe_volatile(call_site_binding, sizeof(call_site_binding));
    js_vbc4_wipe_volatile(route_binding, sizeof(route_binding));
    js_vbc4_wipe_volatile(envelope_binding, sizeof(envelope_binding));
    return ok ? required_size : 0u;
}

static void test_fill_fixture(test_page_fixture *fixture, const unsigned char *descriptor, size_t descriptor_len) {
    static const unsigned char route[] = {0x52u, 0x4Fu, 0x55u, 0x54u, 0x45u, 0x2Du, 0x31u};
    static const unsigned char proof[] = {0x50u, 0x52u, 0x4Fu, 0x4Fu, 0x46u, 0x2Du, 0x31u};
    memset(fixture, 0, sizeof(*fixture));
    fixture->form = JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR;
    fixture->entry_token = UINT64_C(0x1122334455667788);
    fixture->resource_kind = 1u;
    fixture->page_index = 7;
    for (size_t index = 0u; index < sizeof(fixture->encoded_handle); index++) fixture->encoded_handle[index] = (unsigned char)(0x10u + index);
    for (size_t index = 0u; index < sizeof(fixture->locator_token); index++) fixture->locator_token[index] = (unsigned char)(0x40u + index);
    for (size_t index = 0u; index < sizeof(fixture->evaluator_fingerprint); index++) fixture->evaluator_fingerprint[index] = (unsigned char)(0x60u + index);
    for (size_t index = 0u; index < sizeof(fixture->artifact_commitment); index++) fixture->artifact_commitment[index] = (unsigned char)(0x90u + index);
    fixture->descriptor = descriptor;
    fixture->descriptor_len = descriptor_len;
    fixture->route = route;
    fixture->route_len = sizeof(route);
    fixture->raw_call_site_proof = proof;
    fixture->raw_call_site_proof_len = sizeof(proof);
}

static void test_fill_resolved_descriptor(
    js_aken_native_page_resolved_descriptor *resolved,
    const test_page_fixture *fixture,
    const unsigned char *descriptor,
    size_t descriptor_len,
    const unsigned char *route,
    size_t route_len
) {
    memset(resolved, 0, sizeof(*resolved));
    resolved->resource_kind = fixture->resource_kind;
    resolved->page_index = fixture->page_index;
    resolved->encoded_handle = fixture->encoded_handle;
    resolved->encoded_handle_len = sizeof(fixture->encoded_handle);
    resolved->locator_token = fixture->locator_token;
    resolved->locator_token_len = sizeof(fixture->locator_token);
    resolved->evaluator_fingerprint = fixture->evaluator_fingerprint;
    resolved->evaluator_fingerprint_len = sizeof(fixture->evaluator_fingerprint);
    resolved->artifact_commitment = fixture->artifact_commitment;
    resolved->artifact_commitment_len = sizeof(fixture->artifact_commitment);
    resolved->descriptor_encoding = descriptor;
    resolved->descriptor_encoding_len = descriptor_len;
    resolved->route_encoding = route;
    resolved->route_encoding_len = route_len;
}

static int test_inline_transport_and_bindings(void) {
    static const unsigned char descriptor[] = {0x44u, 0x45u, 0x53u, 0x43u, 0x2Du, 0x31u};
    unsigned char encoded[JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE + 1u] = {0};
    unsigned char tampered[JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE + 1u] = {0};
    test_page_fixture fixture;
    js_aken_native_page_request request;
    js_aken_native_page_envelope envelope;
    js_aken_native_page_resolved_descriptor resolved;
    unsigned char changed_fingerprint[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    size_t encoded_len;
    test_fill_fixture(&fixture, descriptor, sizeof(descriptor));
    encoded_len = test_build_envelope(encoded, sizeof(encoded), &fixture);
    TEST_CHECK(encoded_len != 0u);
    memset(&request, 0, sizeof(request));
    request.entry_token = fixture.entry_token;
    request.resource_kind = fixture.resource_kind;
    request.page_index = fixture.page_index;
    request.encoded_handle = fixture.encoded_handle;
    request.encoded_handle_len = sizeof(fixture.encoded_handle);
    request.raw_call_site_proof = fixture.raw_call_site_proof;
    request.raw_call_site_proof_len = fixture.raw_call_site_proof_len;
    memset(&envelope, 0, sizeof(envelope));
    TEST_CHECK(js_aken_native_page_envelope_parse(encoded, encoded_len, &request, &envelope));
    TEST_CHECK(envelope.parsed == 1u);
    TEST_CHECK(envelope.form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR);
    TEST_CHECK(envelope.inline_descriptor_len == sizeof(descriptor));
    test_fill_resolved_descriptor(&resolved, &fixture, descriptor, sizeof(descriptor), fixture.route, fixture.route_len);
    TEST_CHECK(js_aken_native_page_envelope_verify_resolved_bindings(&envelope, &resolved));
    resolved.route_encoding = (const unsigned char *)"other-route";
    resolved.route_encoding_len = sizeof("other-route") - 1u;
    TEST_CHECK(!js_aken_native_page_envelope_verify_resolved_bindings(&envelope, &resolved));
    test_fill_resolved_descriptor(&resolved, &fixture, descriptor, sizeof(descriptor), fixture.route, fixture.route_len);
    memcpy(changed_fingerprint, fixture.evaluator_fingerprint, sizeof(changed_fingerprint));
    changed_fingerprint[0] ^= 0x01u;
    resolved.evaluator_fingerprint = changed_fingerprint;
    TEST_CHECK(!js_aken_native_page_envelope_verify_resolved_bindings(&envelope, &resolved));
    js_aken_native_page_envelope_wipe(&envelope);

    memcpy(tampered, encoded, encoded_len);
    /* A raw proof is not an envelope: this must not bind when substituted. */
    request.raw_call_site_proof = encoded;
    request.raw_call_site_proof_len = encoded_len;
    TEST_CHECK(!js_aken_native_page_envelope_parse(encoded, encoded_len, &request, &envelope));
    request.raw_call_site_proof = fixture.raw_call_site_proof;
    request.raw_call_site_proof_len = fixture.raw_call_site_proof_len;

    /* Handle, locator, fingerprint, commitment, descriptor/proof/route, and final binding are all covered. */
    for (size_t offset = 15u; offset < JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE; offset += 24u) {
        memcpy(tampered, encoded, encoded_len);
        tampered[offset] ^= 0x5Au;
        TEST_CHECK(!js_aken_native_page_envelope_parse(tampered, encoded_len, &request, &envelope));
    }
    memcpy(tampered, encoded, encoded_len);
    tampered[JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE - JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE + 4u] ^= 0x5Au;
    TEST_CHECK(!js_aken_native_page_envelope_parse(tampered, encoded_len, &request, &envelope));
    memcpy(tampered, encoded, encoded_len);
    tampered[encoded_len - 1u] ^= 0x5Au;
    TEST_CHECK(!js_aken_native_page_envelope_parse(tampered, encoded_len, &request, &envelope));
    TEST_CHECK(!js_aken_native_page_envelope_parse(encoded, JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE + 1u, &request, &envelope));
    js_vbc4_wipe_volatile(encoded, sizeof(encoded));
    js_vbc4_wipe_volatile(tampered, sizeof(tampered));
    js_vbc4_wipe_volatile(changed_fingerprint, sizeof(changed_fingerprint));
    js_vbc4_wipe_volatile(&resolved, sizeof(resolved));
    js_vbc4_wipe_volatile(&fixture, sizeof(fixture));
    return 1;
}

static int test_compact_locator_requires_resolved_bindings(void) {
    unsigned char descriptor[JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_INLINE_DESCRIPTOR_SIZE + 1u];
    unsigned char changed_descriptor[sizeof(descriptor)];
    unsigned char encoded[JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE] = {0};
    test_page_fixture fixture;
    js_aken_native_page_request request;
    js_aken_native_page_envelope envelope;
    js_aken_native_page_resolved_descriptor resolved;
    size_t encoded_len;
    for (size_t index = 0u; index < sizeof(descriptor); index++) descriptor[index] = (unsigned char)(index ^ 0xA5u);
    memcpy(changed_descriptor, descriptor, sizeof(descriptor));
    changed_descriptor[sizeof(changed_descriptor) / 2u] ^= 0x01u;
    test_fill_fixture(&fixture, descriptor, sizeof(descriptor));
    fixture.form = JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_COMPACT_LOCATOR;
    encoded_len = test_build_envelope(encoded, sizeof(encoded), &fixture);
    TEST_CHECK(encoded_len == JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE);
    memset(&request, 0, sizeof(request));
    request.entry_token = fixture.entry_token;
    request.resource_kind = fixture.resource_kind;
    request.page_index = fixture.page_index;
    request.encoded_handle = fixture.encoded_handle;
    request.encoded_handle_len = sizeof(fixture.encoded_handle);
    request.raw_call_site_proof = fixture.raw_call_site_proof;
    request.raw_call_site_proof_len = fixture.raw_call_site_proof_len;
    memset(&envelope, 0, sizeof(envelope));
    TEST_CHECK(js_aken_native_page_envelope_parse(encoded, encoded_len, &request, &envelope));
    TEST_CHECK(envelope.form == JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_COMPACT_LOCATOR);
    TEST_CHECK(envelope.inline_descriptor == NULL && envelope.inline_descriptor_len == 0u);
    test_fill_resolved_descriptor(&resolved, &fixture, descriptor, sizeof(descriptor), fixture.route, fixture.route_len);
    TEST_CHECK(js_aken_native_page_envelope_verify_resolved_bindings(&envelope, &resolved));
    resolved.descriptor_encoding = changed_descriptor;
    resolved.descriptor_encoding_len = sizeof(changed_descriptor);
    TEST_CHECK(!js_aken_native_page_envelope_verify_resolved_bindings(&envelope, &resolved));
    js_aken_native_page_envelope_wipe(&envelope);
    js_vbc4_wipe_volatile(descriptor, sizeof(descriptor));
    js_vbc4_wipe_volatile(changed_descriptor, sizeof(changed_descriptor));
    js_vbc4_wipe_volatile(encoded, sizeof(encoded));
    js_vbc4_wipe_volatile(&resolved, sizeof(resolved));
    js_vbc4_wipe_volatile(&fixture, sizeof(fixture));
    return 1;
}

int main(void) {
    if (!test_inline_transport_and_bindings()) return 1;
    if (!test_compact_locator_requires_resolved_bindings()) return 1;
    puts("AKEN native page envelope probe: PASS");
    return 0;
}
