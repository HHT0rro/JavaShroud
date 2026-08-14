#include "js_jni_runtime.h"
#include "js_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "AKEN native locator probe failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
        return 0; \
    } \
} while (0)

/*
 * This probe is linked against a temporary copy of js_jni_runtime.c whose
 * adjacent generated js_aken_page_locator.inc contains the three records
 * produced by the fixture command in the native test invocation.  It keeps
 * the production generated include untouched while exercising the exact
 * compiled-table path.
 */
static const unsigned char TEST_HANDLE_A[JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
    0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
};
static const unsigned char TEST_HANDLE_B[JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE] = {
    0x80u, 0x81u, 0x82u, 0x83u, 0x84u, 0x85u, 0x86u, 0x87u,
    0x88u, 0x89u, 0x8Au, 0x8Bu, 0x8Cu, 0x8Du, 0x8Eu, 0x8Fu,
    0x90u, 0x91u, 0x92u, 0x93u, 0x94u, 0x95u, 0x96u, 0x97u,
};
static const unsigned char TEST_PROOF_A[] = {
    0x41u, 0x4Bu, 0x45u, 0x4Eu, 0x2Du, 0x50u, 0x52u, 0x4Fu, 0x4Fu, 0x46u, 0x2Du, 0x41u,
};

static void test_request_a(js_aken_native_page_request *request) {
    memset(request, 0, sizeof(*request));
    request->entry_token = UINT64_C(0x1122334455667788);
    request->resource_kind = JS_AKEN_NATIVE_PAGE_RESOURCE_KIND_VBC4_METHOD;
    request->page_index = 7;
    request->encoded_handle = TEST_HANDLE_A;
    request->encoded_handle_len = sizeof(TEST_HANDLE_A);
    request->raw_call_site_proof = TEST_PROOF_A;
    request->raw_call_site_proof_len = sizeof(TEST_PROOF_A);
}

static int test_lookup_resolve_and_fail_closed(void) {
    js_aken_native_page_request request;
    js_aken_native_page_locator_record record;
    js_aken_native_page_locator_record missing;
    js_aken_native_page_envelope envelope;
    js_aken_native_page_resolved_descriptor resolved;

    memset(&record, 0, sizeof(record));
    memset(&missing, 0, sizeof(missing));
    memset(&envelope, 0, sizeof(envelope));
    memset(&resolved, 0, sizeof(resolved));
    test_request_a(&request);

    /* All records are validated before this exact unique match is returned. */
    TEST_CHECK(js_aken_native_page_locator_lookup(&request, &record));
    TEST_CHECK(record.parsed == 1u);
    TEST_CHECK(record.entry_token == request.entry_token);
    TEST_CHECK(record.resource_kind == request.resource_kind);
    TEST_CHECK(record.page_index == request.page_index);
    TEST_CHECK(record.encoded_handle_len == sizeof(TEST_HANDLE_A));
    TEST_CHECK(record.native_envelope_len != 0u);
    TEST_CHECK(record.descriptor_encoding_len != 0u);
    TEST_CHECK(record.route_encoding_len != 0u);

    TEST_CHECK(js_aken_native_page_envelope_parse(
        record.native_envelope,
        record.native_envelope_len,
        &request,
        &envelope));
    TEST_CHECK(js_aken_native_page_locator_resolve(&record, &envelope, &resolved));
    TEST_CHECK(resolved.descriptor_encoding == record.descriptor_encoding);
    TEST_CHECK(resolved.descriptor_encoding_len == record.descriptor_encoding_len);
    TEST_CHECK(resolved.route_encoding == record.route_encoding);
    TEST_CHECK(resolved.route_encoding_len == record.route_encoding_len);

    /* Resolver checks the route binding and wipes an output that failed verification. */
    envelope.route_binding[0] ^= 0x01u;
    TEST_CHECK(!js_aken_native_page_locator_resolve(&record, &envelope, &resolved));
    TEST_CHECK(resolved.descriptor_encoding == NULL);
    TEST_CHECK(resolved.route_encoding == NULL);
    js_aken_native_page_envelope_wipe(&envelope);
    TEST_CHECK(js_aken_native_page_envelope_parse(
        record.native_envelope,
        record.native_envelope_len,
        &request,
        &envelope));
    TEST_CHECK(js_aken_native_page_locator_resolve(&record, &envelope, &resolved));

    request.page_index++;
    TEST_CHECK(!js_aken_native_page_locator_lookup(&request, &missing));
    TEST_CHECK(missing.parsed == 0u);
    request.page_index--;

    /* The generated fixture includes two valid records for B: fail closed. */
    request.entry_token = UINT64_C(0x8877665544332211);
    request.page_index = 9;
    request.encoded_handle = TEST_HANDLE_B;
    request.encoded_handle_len = sizeof(TEST_HANDLE_B);
    TEST_CHECK(!js_aken_native_page_locator_lookup(&request, &missing));
    TEST_CHECK(missing.parsed == 0u);

    js_vbc4_wipe_volatile(&resolved, sizeof(resolved));
    js_aken_native_page_envelope_wipe(&envelope);
    js_aken_native_page_locator_record_wipe(&record);
    TEST_CHECK(record.parsed == 0u);
    TEST_CHECK(record.encoded_handle == NULL);
    js_aken_native_page_locator_record_wipe(&missing);
    js_vbc4_wipe_volatile(&request, sizeof(request));
    return 1;
}

int main(void) {
    if (!test_lookup_resolve_and_fail_closed()) return 1;
    puts("AKEN native page locator probe: PASS");
    return 0;
}
