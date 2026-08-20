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

static unsigned char *find_bytes(
    unsigned char *haystack,
    size_t haystack_len,
    const unsigned char *needle,
    size_t needle_len
) {
    if (!haystack || !needle || needle_len == 0u || needle_len > haystack_len) return NULL;
    for (size_t index = 0u; index <= haystack_len - needle_len; index++) {
        if (memcmp(haystack + index, needle, needle_len) == 0) return haystack + index;
    }
    return NULL;
}

static int test_bound_payload_open(void) {
    js_aken_native_page_request request;
    js_aken_native_page_request corrupt_request;
    js_aken_native_page_locator_record record;
    js_aken_native_page_envelope envelope;
    js_aken_native_page_envelope corrupt_envelope;
    js_aken_native_page_resolved_descriptor resolved;
    js_aken_native_page_resolved_descriptor corrupt_resolved;
    js_aken_native_page_descriptor_view descriptor_view;
    js_aken_native_page_descriptor_view corrupt_descriptor_view;
    js_aken_evaluator_binding binding;
    js_aken_native_opened_page opened;
    unsigned char corrupt_proof[sizeof(TEST_RAW_CALL_SITE_PROOF)];
    unsigned char corrupt_fingerprint[sizeof(TEST_EVALUATOR_FINGERPRINT)];
    unsigned char corrupt_layout[sizeof(TEST_LAYOUT_VARIANT)];
    unsigned char corrupt_commitment[sizeof(TEST_ARTIFACT_COMMITMENT)];
    unsigned char corrupt_locator[sizeof(TEST_LOCATOR_TOKEN)];
    unsigned char corrupt_leaf_digest[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char corrupt_mesh_root[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char *tampered_payload = NULL;
    unsigned char *corrupt_descriptor = NULL;
    unsigned char *corrupt_bound_plan = NULL;
    unsigned char *corrupt_route = NULL;
    size_t corrupt_route_len = 0u;
    unsigned char *mutated_field = NULL;
    int ok = 0;

    memset(&request, 0, sizeof(request));
    memset(&corrupt_request, 0, sizeof(corrupt_request));
    memset(&record, 0, sizeof(record));
    memset(&envelope, 0, sizeof(envelope));
    memset(&corrupt_envelope, 0, sizeof(corrupt_envelope));
    memset(&resolved, 0, sizeof(resolved));
    memset(&corrupt_resolved, 0, sizeof(corrupt_resolved));
    memset(&descriptor_view, 0, sizeof(descriptor_view));
    memset(&corrupt_descriptor_view, 0, sizeof(corrupt_descriptor_view));
    memset(&binding, 0, sizeof(binding));
    memset(&opened, 0, sizeof(opened));
    memset(corrupt_proof, 0, sizeof(corrupt_proof));
    memset(corrupt_fingerprint, 0, sizeof(corrupt_fingerprint));
    memset(corrupt_layout, 0, sizeof(corrupt_layout));
    memset(corrupt_commitment, 0, sizeof(corrupt_commitment));
    memset(corrupt_locator, 0, sizeof(corrupt_locator));
    memset(corrupt_leaf_digest, 0, sizeof(corrupt_leaf_digest));
    memset(corrupt_mesh_root, 0, sizeof(corrupt_mesh_root));

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
    TEST_CHECK(js_aken_native_page_descriptor_parse_current(
        &request,
        &envelope,
        &resolved,
        &descriptor_view));
    TEST_CHECK(descriptor_view.parsed == 1u);
    TEST_CHECK(descriptor_view.binding.kind_id == TEST_RESOURCE_KIND);
    TEST_CHECK(descriptor_view.binding.page_index == TEST_PAGE_INDEX);
    TEST_CHECK(descriptor_view.binding.target_size == TEST_TARGET_PAGE_SIZE);
    TEST_CHECK(descriptor_view.binding.logical_identity_len == sizeof(TEST_LOGICAL_IDENTITY));
    TEST_CHECK(memcmp(
        descriptor_view.binding.logical_identity,
        TEST_LOGICAL_IDENTITY,
        sizeof(TEST_LOGICAL_IDENTITY)) == 0);
    TEST_CHECK(descriptor_view.binding.encoded_handle_len == sizeof(TEST_ENCODED_HANDLE));
    TEST_CHECK(memcmp(
        descriptor_view.binding.encoded_handle,
        TEST_ENCODED_HANDLE,
        sizeof(TEST_ENCODED_HANDLE)) == 0);
    /* Current descriptors expose the authenticated v2 plan as an opaque
     * bound_plan slice; the former evaluator_plan_version field was removed
     * from the current ABI and must not be reconstructed in a fixture. */
    TEST_CHECK(descriptor_view.bound_plan_len != 0u);
    TEST_CHECK(descriptor_view.bound_plan != NULL);
    TEST_CHECK(descriptor_view.bound_plan_len == sizeof(TEST_BOUND_PLAN));
    TEST_CHECK(memcmp(descriptor_view.bound_plan, TEST_BOUND_PLAN, sizeof(TEST_BOUND_PLAN)) == 0);
    TEST_CHECK(descriptor_view.route_encoding != NULL);
    TEST_CHECK(descriptor_view.route_encoding_len != 0u);
    TEST_CHECK(descriptor_view.call_site_proof != NULL);
    TEST_CHECK(descriptor_view.call_site_proof_len == sizeof(TEST_RAW_CALL_SITE_PROOF));
    TEST_CHECK(descriptor_view.leaf_identity_encoding != NULL);
    TEST_CHECK(descriptor_view.leaf_identity_encoding_len != 0u);
    TEST_CHECK(descriptor_view.mesh_root != NULL);
    TEST_CHECK(descriptor_view.leaf_digest != NULL);
    TEST_CHECK(js_aken_native_page_descriptor_verify_payload_mesh(
        &descriptor_view,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD)));
    binding = descriptor_view.binding;

    corrupt_descriptor = (unsigned char *)malloc(resolved.descriptor_encoding_len);
    TEST_CHECK(corrupt_descriptor != NULL);
    memcpy(corrupt_descriptor, resolved.descriptor_encoding, resolved.descriptor_encoding_len);
    corrupt_descriptor[resolved.descriptor_encoding_len - 1u] ^= 0x01u;
    corrupt_resolved = resolved;
    corrupt_resolved.descriptor_encoding = corrupt_descriptor;
    TEST_CHECK(!js_aken_native_page_descriptor_parse_current(
        &request,
        &envelope,
        &corrupt_resolved,
        &corrupt_descriptor_view));
    TEST_CHECK(corrupt_descriptor_view.parsed == 0u);
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);

    memcpy(corrupt_descriptor, resolved.descriptor_encoding, resolved.descriptor_encoding_len);
    mutated_field = find_bytes(
        corrupt_descriptor,
        resolved.descriptor_encoding_len,
        descriptor_view.resource_path,
        descriptor_view.resource_path_len);
    TEST_CHECK(mutated_field != NULL);
    *mutated_field = (unsigned char)'\\';
    TEST_CHECK(!js_aken_native_page_descriptor_parse_current(
        &request,
        &envelope,
        &corrupt_resolved,
        &corrupt_descriptor_view));
    TEST_CHECK(corrupt_descriptor_view.parsed == 0u);
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);

    memcpy(corrupt_descriptor, resolved.descriptor_encoding, resolved.descriptor_encoding_len);
    mutated_field = find_bytes(
        corrupt_descriptor,
        resolved.descriptor_encoding_len,
        TEST_CODEC_VARIANT,
        sizeof(TEST_CODEC_VARIANT));
    TEST_CHECK(mutated_field != NULL);
    *mutated_field = (unsigned char)'x';
    TEST_CHECK(!js_aken_native_page_descriptor_parse_current(
        &request,
        &envelope,
        &corrupt_resolved,
        &corrupt_descriptor_view));
    TEST_CHECK(corrupt_descriptor_view.parsed == 0u);
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);

    memcpy(corrupt_descriptor, resolved.descriptor_encoding, resolved.descriptor_encoding_len);
    mutated_field = find_bytes(
        corrupt_descriptor,
        resolved.descriptor_encoding_len,
        TEST_LAYOUT_VARIANT,
        sizeof(TEST_LAYOUT_VARIANT));
    TEST_CHECK(mutated_field != NULL);
    mutated_field[sizeof(TEST_LAYOUT_VARIANT) - 1u] = (unsigned char)'B';
    TEST_CHECK(!js_aken_native_page_descriptor_parse_current(
        &request,
        &envelope,
        &corrupt_resolved,
        &corrupt_descriptor_view));
    TEST_CHECK(corrupt_descriptor_view.parsed == 0u);
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);

    TEST_CHECK(js_aken_native_page_open_current_view_payload(
        &request,
        &envelope,
        &resolved,
        &descriptor_view,
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
    TEST_CHECK(!js_aken_native_page_descriptor_verify_payload_mesh(
        &descriptor_view,
        tampered_payload,
        sizeof(TEST_ENCODED_PAYLOAD)));
    TEST_CHECK(!js_aken_native_page_open_current_view_payload(
        &request,
        &envelope,
        &resolved,
        &descriptor_view,
        tampered_payload,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));

    memcpy(corrupt_leaf_digest, descriptor_view.leaf_digest, sizeof(corrupt_leaf_digest));
    corrupt_leaf_digest[0] ^= 0x01u;
    corrupt_descriptor_view = descriptor_view;
    corrupt_descriptor_view.leaf_digest = corrupt_leaf_digest;
    TEST_CHECK(!js_aken_native_page_descriptor_verify_payload_mesh(
        &corrupt_descriptor_view,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD)));
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);

    memcpy(corrupt_mesh_root, descriptor_view.mesh_root, sizeof(corrupt_mesh_root));
    corrupt_mesh_root[0] ^= 0x01u;
    corrupt_descriptor_view = descriptor_view;
    corrupt_descriptor_view.mesh_root = corrupt_mesh_root;
    TEST_CHECK(!js_aken_native_page_descriptor_verify_payload_mesh(
        &corrupt_descriptor_view,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD)));
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);

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
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        descriptor_view.bound_plan,
        descriptor_view.bound_plan_len,
        descriptor_view.route_encoding,
        descriptor_view.route_encoding_len,
        descriptor_view.call_site_proof,
        descriptor_view.call_site_proof_len,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));
    binding.evaluator_fingerprint = TEST_EVALUATOR_FINGERPRINT;

    memcpy(corrupt_layout, TEST_LAYOUT_VARIANT, sizeof(corrupt_layout));
    corrupt_layout[sizeof(corrupt_layout) - 1u] = (unsigned char)'B';
    binding.layout_variant = corrupt_layout;
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        descriptor_view.bound_plan,
        descriptor_view.bound_plan_len,
        descriptor_view.route_encoding,
        descriptor_view.route_encoding_len,
        descriptor_view.call_site_proof,
        descriptor_view.call_site_proof_len,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));
    binding.layout_variant = TEST_LAYOUT_VARIANT;

    corrupt_bound_plan = (unsigned char *)malloc(sizeof(TEST_BOUND_PLAN));
    TEST_CHECK(corrupt_bound_plan != NULL);
    memcpy(corrupt_bound_plan, TEST_BOUND_PLAN, sizeof(TEST_BOUND_PLAN));
    corrupt_bound_plan[sizeof(TEST_BOUND_PLAN) - 1u] ^= 0x01u;
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        corrupt_bound_plan,
        sizeof(TEST_BOUND_PLAN),
        descriptor_view.route_encoding,
        descriptor_view.route_encoding_len,
        descriptor_view.call_site_proof,
        descriptor_view.call_site_proof_len,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));

    memcpy(corrupt_proof, TEST_RAW_CALL_SITE_PROOF, sizeof(corrupt_proof));
    corrupt_proof[0] ^= 0x01u;
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        descriptor_view.bound_plan,
        descriptor_view.bound_plan_len,
        descriptor_view.route_encoding,
        descriptor_view.route_encoding_len,
        corrupt_proof,
        sizeof(corrupt_proof),
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));

    corrupt_route_len = descriptor_view.route_encoding_len;
    corrupt_route = (unsigned char *)malloc(corrupt_route_len);
    TEST_CHECK(corrupt_route != NULL);
    memcpy(corrupt_route, descriptor_view.route_encoding, corrupt_route_len);
    corrupt_route[0] ^= 0x01u;
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        descriptor_view.bound_plan,
        descriptor_view.bound_plan_len,
        corrupt_route,
        corrupt_route_len,
        descriptor_view.call_site_proof,
        descriptor_view.call_site_proof_len,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));

    memcpy(corrupt_commitment, TEST_ARTIFACT_COMMITMENT, sizeof(corrupt_commitment));
    corrupt_commitment[0] ^= 0x01u;
    binding.artifact_commitment = corrupt_commitment;
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        descriptor_view.bound_plan,
        descriptor_view.bound_plan_len,
        descriptor_view.route_encoding,
        descriptor_view.route_encoding_len,
        descriptor_view.call_site_proof,
        descriptor_view.call_site_proof_len,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));
    binding.artifact_commitment = TEST_ARTIFACT_COMMITMENT;

    memcpy(corrupt_locator, TEST_LOCATOR_TOKEN, sizeof(corrupt_locator));
    corrupt_locator[0] ^= 0x01u;
    binding.locator_token = corrupt_locator;
    TEST_CHECK(!js_aken_native_page_open_bound_plan_payload(
        &request,
        &envelope,
        &resolved,
        &binding,
        descriptor_view.bound_plan,
        descriptor_view.bound_plan_len,
        descriptor_view.route_encoding,
        descriptor_view.route_encoding_len,
        descriptor_view.call_site_proof,
        descriptor_view.call_site_proof_len,
        TEST_ENCODED_PAYLOAD,
        sizeof(TEST_ENCODED_PAYLOAD),
        &opened));
    TEST_CHECK(opened_page_is_empty(&opened));
    binding.locator_token = TEST_LOCATOR_TOKEN;

    ok = 1;
cleanup:
    js_aken_native_opened_page_wipe(&opened);
    if (tampered_payload) {
        js_vbc4_wipe_volatile(tampered_payload, sizeof(TEST_ENCODED_PAYLOAD));
        free(tampered_payload);
    }
    if (corrupt_descriptor) {
        js_vbc4_wipe_volatile(corrupt_descriptor, resolved.descriptor_encoding_len);
        free(corrupt_descriptor);
    }
    if (corrupt_bound_plan) {
        js_vbc4_wipe_volatile(corrupt_bound_plan, sizeof(TEST_BOUND_PLAN));
        free(corrupt_bound_plan);
    }
    if (corrupt_route) {
        js_vbc4_wipe_volatile(corrupt_route, corrupt_route_len);
        free(corrupt_route);
    }
    js_vbc4_wipe_volatile(corrupt_proof, sizeof(corrupt_proof));
    js_vbc4_wipe_volatile(corrupt_fingerprint, sizeof(corrupt_fingerprint));
    js_vbc4_wipe_volatile(corrupt_layout, sizeof(corrupt_layout));
    js_vbc4_wipe_volatile(corrupt_commitment, sizeof(corrupt_commitment));
    js_vbc4_wipe_volatile(corrupt_locator, sizeof(corrupt_locator));
    js_vbc4_wipe_volatile(corrupt_leaf_digest, sizeof(corrupt_leaf_digest));
    js_vbc4_wipe_volatile(corrupt_mesh_root, sizeof(corrupt_mesh_root));
    js_aken_native_page_envelope_wipe(&corrupt_envelope);
    js_aken_native_page_descriptor_view_wipe(&corrupt_descriptor_view);
    js_aken_native_page_descriptor_view_wipe(&descriptor_view);
    js_vbc4_wipe_volatile(&corrupt_resolved, sizeof(corrupt_resolved));
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
