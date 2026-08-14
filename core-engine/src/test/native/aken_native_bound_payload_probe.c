#include "js_jni_runtime.h"
#include "js_vm_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aken_native_bound_payload_fixture.inc"

#define TEST_CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "AKEN native bound payload probe failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
        goto cleanup; \
    } \
} while (0)

static int opened_page_is_empty(const js_aken_native_opened_page *page) {
    return page && page->bytes == NULL && page->length == 0u;
}

static int test_bound_payload_open(void) {
    js_aken_native_page_request request;
    js_aken_native_page_request corrupt_request;
    js_aken_native_page_locator_record record;
    js_aken_native_page_envelope envelope;
    js_aken_native_page_envelope corrupt_envelope;
    js_aken_native_page_resolved_descriptor resolved;
    js_aken_evaluator_binding binding;
    js_aken_evaluator_fragment corrupt_fragments[JS_AKEN_EVALUATOR_FRAGMENT_COUNT];
    js_aken_native_opened_page opened;
    unsigned char corrupt_proof[sizeof(TEST_RAW_CALL_SITE_PROOF)];
    unsigned char corrupt_fingerprint[sizeof(TEST_EVALUATOR_FINGERPRINT)];
    unsigned char corrupt_layout[sizeof(TEST_LAYOUT_VARIANT)];
    unsigned char corrupt_shape[sizeof(TEST_FRAGMENT_0_SHAPE)];
    unsigned char *tampered_payload = NULL;
    int ok = 0;

    memset(&request, 0, sizeof(request));
    memset(&corrupt_request, 0, sizeof(corrupt_request));
    memset(&record, 0, sizeof(record));
    memset(&envelope, 0, sizeof(envelope));
    memset(&corrupt_envelope, 0, sizeof(corrupt_envelope));
    memset(&resolved, 0, sizeof(resolved));
    memset(&binding, 0, sizeof(binding));
    memset(corrupt_fragments, 0, sizeof(corrupt_fragments));
    memset(&opened, 0, sizeof(opened));
    memset(corrupt_proof, 0, sizeof(corrupt_proof));
    memset(corrupt_fingerprint, 0, sizeof(corrupt_fingerprint));
    memset(corrupt_layout, 0, sizeof(corrupt_layout));
    memset(corrupt_shape, 0, sizeof(corrupt_shape));

    request.entry_token = TEST_ENTRY_TOKEN;
    request.resource_kind = TEST_RESOURCE_KIND;
    request.page_index = TEST_PAGE_INDEX;
    request.encoded_handle = TEST_ENCODED_HANDLE;
    request.encoded_handle_len = sizeof(TEST_ENCODED_HANDLE);
    request.raw_call_site_proof = TEST_RAW_CALL_SITE_PROOF;
    request.raw_call_site_proof_len = sizeof(TEST_RAW_CALL_SITE_PROOF);

    TEST_CHECK(js_aken_native_page_locator_lookup(&request, &record));
    TEST_CHECK(js_aken_native_page_envelope_parse(
        record.native_envelope,
        record.native_envelope_len,
        &request,
        &envelope));
    TEST_CHECK(js_aken_native_page_locator_resolve(&record, &envelope, &resolved));

    binding.kind_id = TEST_RESOURCE_KIND;
    binding.logical_identity = TEST_LOGICAL_IDENTITY;
    binding.logical_identity_len = sizeof(TEST_LOGICAL_IDENTITY);
    binding.page_index = TEST_PAGE_INDEX;
    binding.target_size = TEST_TARGET_PAGE_SIZE;
    binding.codec_variant = TEST_CODEC_VARIANT;
    binding.codec_variant_len = sizeof(TEST_CODEC_VARIANT);
    binding.layout_variant = TEST_LAYOUT_VARIANT;
    binding.layout_variant_len = sizeof(TEST_LAYOUT_VARIANT);
    binding.encoded_handle = TEST_ENCODED_HANDLE;
    binding.encoded_handle_len = sizeof(TEST_ENCODED_HANDLE);
    binding.locator_token = TEST_LOCATOR_TOKEN;
    binding.locator_token_len = sizeof(TEST_LOCATOR_TOKEN);
    binding.evaluator_fingerprint = TEST_EVALUATOR_FINGERPRINT;
    binding.evaluator_fingerprint_len = sizeof(TEST_EVALUATOR_FINGERPRINT);
    binding.artifact_commitment = TEST_ARTIFACT_COMMITMENT;
    binding.artifact_commitment_len = sizeof(TEST_ARTIFACT_COMMITMENT);

    TEST_CHECK(js_aken_native_page_open_bound_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        TEST_EVALUATOR_FRAGMENTS,
        JS_AKEN_EVALUATOR_FRAGMENT_COUNT,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened.bytes != NULL);
    TEST_CHECK(opened.length == sizeof(TEST_EXPECTED_PLAINTEXT));
    TEST_CHECK(memcmp(opened.bytes, TEST_EXPECTED_PLAINTEXT, sizeof(TEST_EXPECTED_PLAINTEXT)) == 0);
    js_aken_native_opened_page_wipe(&opened);
    TEST_CHECK(opened_page_is_empty(&opened));

    tampered_payload = (unsigned char *)malloc(sizeof(TEST_ENCODED_PAYLOAD));
    TEST_CHECK(tampered_payload != NULL);
    memcpy(tampered_payload, TEST_ENCODED_PAYLOAD, sizeof(TEST_ENCODED_PAYLOAD));
    tampered_payload[0] ^= 0x01u;
    TEST_CHECK(!js_aken_native_page_open_bound_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        TEST_EVALUATOR_FRAGMENTS,
        JS_AKEN_EVALUATOR_FRAGMENT_COUNT,
        tampered_payload,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));

    memcpy(corrupt_proof, TEST_RAW_CALL_SITE_PROOF, sizeof(corrupt_proof));
    corrupt_proof[0] ^= 0x01u;
    corrupt_request = request;
    corrupt_request.raw_call_site_proof = corrupt_proof;
    corrupt_request.raw_call_site_proof_len = sizeof(corrupt_proof);
    TEST_CHECK(!js_aken_native_page_envelope_parse(
        record.native_envelope,
        record.native_envelope_len,
        &corrupt_request,
        &corrupt_envelope));
    js_aken_native_page_envelope_wipe(&corrupt_envelope);
    TEST_CHECK(corrupt_envelope.parsed == 0u);

    memcpy(corrupt_fingerprint, TEST_EVALUATOR_FINGERPRINT, sizeof(corrupt_fingerprint));
    corrupt_fingerprint[0] ^= 0x01u;
    binding.evaluator_fingerprint = corrupt_fingerprint;
    TEST_CHECK(!js_aken_native_page_open_bound_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        TEST_EVALUATOR_FRAGMENTS,
        JS_AKEN_EVALUATOR_FRAGMENT_COUNT,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));
    binding.evaluator_fingerprint = TEST_EVALUATOR_FINGERPRINT;

    memcpy(corrupt_layout, TEST_LAYOUT_VARIANT, sizeof(corrupt_layout));
    corrupt_layout[sizeof(corrupt_layout) - 1u] = (unsigned char)'B';
    binding.layout_variant = corrupt_layout;
    TEST_CHECK(!js_aken_native_page_open_bound_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        TEST_EVALUATOR_FRAGMENTS,
        JS_AKEN_EVALUATOR_FRAGMENT_COUNT,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));
    binding.layout_variant = TEST_LAYOUT_VARIANT;

    memcpy(corrupt_fragments, TEST_EVALUATOR_FRAGMENTS, sizeof(corrupt_fragments));
    memcpy(corrupt_shape, TEST_FRAGMENT_0_SHAPE, sizeof(corrupt_shape));
    corrupt_shape[0] ^= 0x01u;
    corrupt_fragments[0].shape = corrupt_shape;
    TEST_CHECK(!js_aken_native_page_open_bound_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        corrupt_fragments,
        JS_AKEN_EVALUATOR_FRAGMENT_COUNT,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));

    ok = 1;
cleanup:
    js_aken_native_opened_page_wipe(&opened);
    if (tampered_payload) {
        js_vbc4_wipe_volatile(tampered_payload, sizeof(TEST_ENCODED_PAYLOAD));
        free(tampered_payload);
    }
    js_vbc4_wipe_volatile(corrupt_proof, sizeof(corrupt_proof));
    js_vbc4_wipe_volatile(corrupt_fingerprint, sizeof(corrupt_fingerprint));
    js_vbc4_wipe_volatile(corrupt_layout, sizeof(corrupt_layout));
    js_vbc4_wipe_volatile(corrupt_shape, sizeof(corrupt_shape));
    js_vbc4_wipe_volatile(corrupt_fragments, sizeof(corrupt_fragments));
    js_aken_native_page_envelope_wipe(&corrupt_envelope);
    js_vbc4_wipe_volatile(&resolved, sizeof(resolved));
    js_aken_native_page_envelope_wipe(&envelope);
    js_aken_native_page_locator_record_wipe(&record);
    js_vbc4_wipe_volatile(&corrupt_request, sizeof(corrupt_request));
    js_vbc4_wipe_volatile(&request, sizeof(request));
    return ok;
}

int main(void) {
    if (!test_bound_payload_open()) return 1;
    puts("AKEN native bound payload probe: PASS");
    return 0;
}
