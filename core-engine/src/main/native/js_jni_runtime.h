#ifndef JS_JNI_RUNTIME_H
#define JS_JNI_RUNTIME_H

#include <jni.h>
#include "js_native_common.h"

typedef struct {
    int initialized;
    jclass object_class;
    jclass string_class;
    jclass class_loader_class;
    jclass byte_array_class;
    jclass class_class;
    jclass thread_class;
    jclass input_stream_class;
    jclass string_builder_class;
    jclass runtime_exception_class;
    jclass security_exception_class;
    jclass throwable_class;
    jclass stack_trace_element_class;
    jclass reflect_array_class;
    jclass system_class;
    jclass integer_class;
    jclass boolean_class;
    jclass byte_class;
    jclass short_class;
    jclass character_class;
    jclass long_class;
    jclass float_class;
    jclass double_class;
    jclass void_class;
    jmethodID class_loader_get_resource_as_stream;
    jmethodID class_loader_load_class;
    jmethodID class_loader_define_class;
    jmethodID class_loader_define_class_pd;
    jmethodID class_get_class_loader;
    jmethodID class_get_name;
    jmethodID class_get_resource_as_stream;
    jmethodID class_is_array;
    jmethodID class_get_component_type;
    jmethodID thread_current_thread;
    jmethodID thread_get_context_class_loader;
    jmethodID input_stream_read_all_bytes;
    jmethodID input_stream_close;
    jmethodID string_builder_init;
    jmethodID string_builder_append_string;
    jmethodID string_builder_to_string;
    jmethodID runtime_exception_init;
    jmethodID throwable_set_stack_trace;
    jmethodID stack_trace_element_init;
    jmethodID integer_int_value;
    jmethodID boolean_boolean_value;
    jmethodID byte_byte_value;
    jmethodID short_short_value;
    jmethodID character_char_value;
    jmethodID long_long_value;
    jmethodID float_float_value;
    jmethodID double_double_value;
    jmethodID integer_value_of;
    jmethodID boolean_value_of;
    jmethodID byte_value_of;
    jmethodID short_value_of;
    jmethodID character_value_of;
    jmethodID long_value_of;
    jmethodID float_value_of;
    jmethodID double_value_of;
    jmethodID string_value_of_object;
    jmethodID string_value_of_int;
    jmethodID string_value_of_long;
    jmethodID string_value_of_float;
    jmethodID string_value_of_double;
    jmethodID string_value_of_boolean;
    jmethodID string_value_of_char;
    jmethodID reflect_array_new_instance_dims;
    jmethodID reflect_array_new_instance_len;
    jmethodID system_arraycopy;
    jfieldID integer_type_field;
    jfieldID boolean_type_field;
    jfieldID byte_type_field;
    jfieldID short_type_field;
    jfieldID character_type_field;
    jfieldID long_type_field;
    jfieldID float_type_field;
    jfieldID double_type_field;
    jfieldID void_type_field;
    jfieldID integer_value_field;
    jfieldID boolean_value_field;
    jfieldID byte_value_field;
    jfieldID short_value_field;
    jfieldID character_value_field;
    jfieldID long_value_field;
    jfieldID float_value_field;
    jfieldID double_value_field;
} js_jni_cache_state;

JS_HIDDEN extern js_jni_cache_state js_jni_cache;
JS_HIDDEN int js_jni_cache_init(JNIEnv *env);
JS_HIDDEN void js_jni_cache_destroy(JNIEnv *env);
/* Register helper natives whose final class/method names are keyed by the
 * runtime anchor.  JNI_OnLoad runs before the boot envelope installs that
 * anchor, so the boot-material installation path invokes this once the key
 * slots are ready. */
JS_HIDDEN int js_jni_register_deferred_natives(JNIEnv *env);
JS_HIDDEN jclass js_vm_find_registration_class(JNIEnv *env, const char *class_name);
JS_HIDDEN char* js_lookup_bound_class(JNIEnv *env, const char *original);
JS_HIDDEN char* js_lookup_bound_method(JNIEnv *env, const char *original_class, const char *method_name, const char *signature);
JS_HIDDEN void js_vm_mark_hot_integrity_baseline_clean(void);
JS_HIDDEN void js_runtime_on_unload_cleanup(JNIEnv *env);

/*
 * Internal AKEN-7 evaluator contract.  This is deliberately a native-only
 * page-local primitive, not a JNI ABI and not a generic resource decoder.
 * The future typed page route must supply one already-authenticated descriptor
 * binding plus exactly seven fragments for the current handle only.
 */
#define JS_AKEN_EVALUATOR_STATE_WIDTH 32u
#define JS_AKEN_EVALUATOR_FRAGMENT_COUNT 7u

typedef struct {
    uint8_t kind_id;
    const unsigned char *logical_identity;
    size_t logical_identity_len;
    jint page_index;
    jint target_size;
    const unsigned char *codec_variant;
    size_t codec_variant_len;
    const unsigned char *layout_variant;
    size_t layout_variant_len;
    const unsigned char *encoded_handle;
    size_t encoded_handle_len;
    const unsigned char *locator_token;
    size_t locator_token_len;
    const unsigned char *evaluator_fingerprint;
    size_t evaluator_fingerprint_len;
    /* Public canonical commitment expected from the seven dispersed shape shares. */
    const unsigned char *artifact_commitment;
    size_t artifact_commitment_len;
} js_aken_evaluator_binding;

typedef struct {
    jint ordinal;
    jint family;
    const unsigned char *shape;
    size_t shape_len;
    const unsigned char *call_token;
    size_t call_token_len;
    const uint32_t *table_permutation;
    size_t table_permutation_len;
} js_aken_evaluator_fragment;

/*
 * Reconstructs exactly one current-page 32-byte DEK from the complete AKEN-7
 * graph after validating all page bindings, fragment tags, and the canonical
 * artifact commitment reconstructed from the graph's dispersed shape shares.
 * The caller owns out_dek and must use it only in the terminal page-open scope
 * before wiping it with js_vbc4_wipe_volatile(). Any malformed or incomplete
 * graph returns 0 and clears out_dek.
 */
JS_HIDDEN int js_aken_evaluator_recover_dek(
    const js_aken_evaluator_binding *binding,
    const js_aken_evaluator_fragment *fragments,
    size_t fragment_count,
    unsigned char out_dek[JS_AKEN_EVALUATOR_STATE_WIDTH]
);

/*
 * Internal AKEN v4 current-page envelope contract.  The envelope is a
 * locator-private record and is deliberately separate from the typed JNI
 * call-site proof: callers give parse() the envelope bytes plus the original
 * raw proof that the typed bridge received.  No member here is a JNI ABI,
 * resource decoder, resource catalog, or key-export surface.
 *
 * Inline envelopes carry the exact descriptor encoding.  Compact envelopes
 * intentionally retain only fixed-size bindings; an artifact-specific native
 * locator must subsequently supply its one resolved descriptor and route to
 * verify_resolved_bindings() before a page-open path can use the record.
 */
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE 4096u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_VERSION 1u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_INLINE_DESCRIPTOR 1u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_FORM_COMPACT_LOCATOR 2u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE 24u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE 16u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE 32u
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE \
    (1u + 1u + 8u + 1u + 4u + JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE + \
        JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE + \
        (6u * JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE))
#define JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_INLINE_DESCRIPTOR_SIZE \
    (JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE - JS_AKEN_NATIVE_PAGE_ENVELOPE_FIXED_SIZE - 4u)
#define JS_AKEN_NATIVE_PAGE_DESCRIPTOR_MAX_SIZE (384u * 1024u)
#define JS_AKEN_NATIVE_PAGE_ROUTE_MAX_SIZE (128u * 1024u)
#define JS_AKEN_NATIVE_PAGE_RESOURCE_KIND_VBC4_METHOD 1u

/* Generated compiler-record limits; records themselves remain opaque. */
#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_VERSION 2u
#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_BINDING_SIZE JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE
#define JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_RECORD_COUNT 65535u
#define JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_RECORD_SIZE (512u * 1024u)
#define JS_AKEN_NATIVE_PAGE_LOCATOR_MAX_BLOB_SIZE (64u * 1024u * 1024u)

typedef struct {
    /* Expected current-page values from the typed route / generated locator. */
    uint64_t entry_token;
    uint8_t resource_kind;
    jint page_index;
    const unsigned char *encoded_handle;
    size_t encoded_handle_len;
    /* This is the original typed JNI proof, never an encoded envelope. */
    const unsigned char *raw_call_site_proof;
    size_t raw_call_site_proof_len;
} js_aken_native_page_request;

/*
 * One verified record borrowed from the generated native locator blob.  The
 * pointed-to frames stay owned by that immutable compiler input; wipe() clears
 * only this metadata and never writes the blob.
 */
typedef struct {
    uint8_t parsed;
    uint64_t entry_token;
    uint8_t resource_kind;
    jint page_index;
    const unsigned char *encoded_handle;
    size_t encoded_handle_len;
    const unsigned char *native_envelope;
    size_t native_envelope_len;
    const unsigned char *descriptor_encoding;
    size_t descriptor_encoding_len;
    const unsigned char *route_encoding;
    size_t route_encoding_len;
    /*
     * Public VBC4 serialization state-binding digest. This is copied only from
     * the build-scoped layout digest into the generated current-page record so
     * the AKEN path never asks the retired boot-material runtime for it.
     */
    const unsigned char *vbc4_state_binding_layout_digest;
    size_t vbc4_state_binding_layout_digest_len;
} js_aken_native_page_locator_record;

typedef struct {
    /* Set only by a successful parse(); resolver checks require this marker. */
    uint8_t parsed;
    uint8_t form;
    uint64_t entry_token;
    uint8_t resource_kind;
    jint page_index;
    unsigned char encoded_handle[JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE];
    unsigned char locator_token[JS_AKEN_NATIVE_PAGE_ENVELOPE_LOCATOR_SIZE];
    unsigned char evaluator_fingerprint[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char artifact_commitment[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char descriptor_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char call_site_proof_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    unsigned char route_binding[JS_AKEN_NATIVE_PAGE_ENVELOPE_DIGEST_SIZE];
    /* Borrowed from encoded envelope bytes; wipe() never writes this input. */
    const unsigned char *inline_descriptor;
    size_t inline_descriptor_len;
} js_aken_native_page_envelope;

/*
 * One artifact-specific locator result for the envelope's current page.  The
 * locator owns the pointed-to descriptor and route bytes; this compact
 * binding primitive neither resolves them nor makes them available to Java.
 */
typedef struct {
    uint8_t resource_kind;
    jint page_index;
    const unsigned char *encoded_handle;
    size_t encoded_handle_len;
    const unsigned char *locator_token;
    size_t locator_token_len;
    const unsigned char *evaluator_fingerprint;
    size_t evaluator_fingerprint_len;
    const unsigned char *artifact_commitment;
    size_t artifact_commitment_len;
    const unsigned char *descriptor_encoding;
    size_t descriptor_encoding_len;
    const unsigned char *route_encoding;
    size_t route_encoding_len;
} js_aken_native_page_resolved_descriptor;

/*
 * Borrowed, current-page-only view over one verified AKEN runtime descriptor.
 * The parser never allocates or exposes a catalog: byte/string frames point
 * into the already locator-bound descriptor; only the native-endian evaluator
 * permutation rows are copied for immediate terminal evaluation.  wipe() must
 * run before the surrounding locator/envelope/descriptor lifetime ends.
 */
typedef struct {
    uint8_t parsed;
    js_aken_evaluator_binding binding;
    js_aken_evaluator_fragment fragments[JS_AKEN_EVALUATOR_FRAGMENT_COUNT];
    uint32_t fragment_permutations[JS_AKEN_EVALUATOR_FRAGMENT_COUNT][JS_AKEN_EVALUATOR_STATE_WIDTH];
    /* Exact route/proof leaf encoding used only for the current mesh leaf. */
    const unsigned char *leaf_identity_encoding;
    size_t leaf_identity_encoding_len;
    const unsigned char *mesh_root;
    const unsigned char *leaf_digest;
    const unsigned char *merkle_siblings[64u];
    uint8_t merkle_sibling_is_left[64u];
    size_t merkle_sibling_count;
    const unsigned char *resource_path;
    size_t resource_path_len;
    const unsigned char *logical_binding_path;
    size_t logical_binding_path_len;
    uint32_t resource_offset;
    uint32_t stored_length;
} js_aken_native_page_descriptor_view;

/*
 * Strictly parses at most one 4096-byte envelope, verifies the complete
 * envelope binding, and binds it to the independently supplied raw proof and
 * expected current-page request.  Inline descriptor bindings are checked
 * immediately.  Compact records succeed only as pending resolver records and
 * require js_aken_native_page_envelope_verify_resolved_bindings() next.
 */
JS_HIDDEN int js_aken_native_page_envelope_parse(
    const unsigned char *encoded_envelope,
    size_t encoded_envelope_len,
    const js_aken_native_page_request *request,
    js_aken_native_page_envelope *out_envelope
);

/*
 * Verifies one resolver-supplied current-page identity, descriptor, and route
 * against a parsed envelope.  It performs binding checks only; it does not
 * parse arbitrary resources, decrypt a payload, derive a key, or expose data
 * to Java.  For inline form the descriptor bytes must exactly equal the inline
 * frame; compact form requires this check before use.
 */
JS_HIDDEN int js_aken_native_page_envelope_verify_resolved_bindings(
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved
);

/* Clears copied public bindings and borrowed-pointer metadata in one output record. */
JS_HIDDEN void js_aken_native_page_envelope_wipe(js_aken_native_page_envelope *envelope);

/*
 * Resolves exactly one record from the generated compiler locator. lookup()
 * validates the entire opaque table and succeeds only for one exact request
 * match. resolve() binds that record's descriptor and route to an already
 * parsed envelope, retains the verified descriptor in out_resolved for the
 * immediate page-opener scope, and never exposes a generic decoder or catalog.
 */
JS_HIDDEN int js_aken_native_page_locator_lookup(
    const js_aken_native_page_request *request,
    js_aken_native_page_locator_record *out_record
);
JS_HIDDEN int js_aken_native_page_locator_resolve(
    const js_aken_native_page_locator_record *record,
    const js_aken_native_page_envelope *envelope,
    js_aken_native_page_resolved_descriptor *out_resolved
);
/*
 * Parses exactly the current resolver-bound descriptor and validates its route,
 * proof and AKEN-7 graph against request/envelope/resolved bindings.  It has no
 * arbitrary descriptor/resource entry point and does not yet load a payload.
 */
JS_HIDDEN int js_aken_native_page_descriptor_parse_current(
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved,
    js_aken_native_page_descriptor_view *out_view
);
JS_HIDDEN void js_aken_native_page_descriptor_view_wipe(js_aken_native_page_descriptor_view *view);
/* Verifies only the exact encrypted payload selected by this parsed current-page view. */
JS_HIDDEN int js_aken_native_page_descriptor_verify_payload_mesh(
    const js_aken_native_page_descriptor_view *view,
    const unsigned char *encoded_payload,
    size_t encoded_payload_len
);
JS_HIDDEN void js_aken_native_page_locator_record_wipe(js_aken_native_page_locator_record *record);

/*
 * Native-only ownership for one opened current page.  This is intentionally
 * not a JNI type and has no enumeration or arbitrary-resource decode API.
 * Callers must wipe it immediately after the page-local VM/string/class/chunk
 * consumer finishes with the plaintext.
 */
typedef struct {
    unsigned char *bytes;
    size_t length;
} js_aken_native_opened_page;

/*
 * Low-level terminal codec primitive for one page slice that has already been
 * selected by a native current-page resolver.  The supplied request, parsed
 * envelope, resolved descriptor, evaluator binding, and AKEN-7 graph must all
 * describe that same page. Its payload parameter is native-private compiler
 * input: no JNI entry point exposes this signature, and the future
 * descriptor/route/proof parser is responsible for obtaining the exact route
 * slice before calling it. The function reconstructs the page-local DEK,
 * authenticates the AKEN AES-256-GCM frame and AAD bindings, transfers the
 * resulting plaintext into [out_page], then wipes every transient buffer and
 * the DEK. On failure it returns 0 and leaves [out_page] wiped.
 */
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
);
/* Parser-driven native page opener: mesh-authenticates the current payload before terminal AEAD open. */
JS_HIDDEN int js_aken_native_page_open_current_view_payload(
    const js_aken_native_page_request *request,
    const js_aken_native_page_envelope *envelope,
    const js_aken_native_page_resolved_descriptor *resolved,
    const js_aken_native_page_descriptor_view *view,
    const unsigned char *encoded_payload,
    size_t encoded_payload_len,
    js_aken_native_opened_page *out_page
);
JS_HIDDEN void js_aken_native_opened_page_wipe(js_aken_native_opened_page *page);

#define JS_NATIVE_ABI_TABLE_VERSION 10u

typedef struct js_native_abi_table {
    unsigned int version;
    jint (JNICALL *native_init)(JNIEnv *env, jclass cls, jstring platform);
    jint (JNICALL *native_verify)(JNIEnv *env, jclass cls, jbyteArray data, jbyteArray expected_mac);
    jint (JNICALL *native_heartbeat)(JNIEnv *env, jclass cls);
    jbyteArray (JNICALL *native_decrypt_aes)(JNIEnv *env, jclass cls, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr);
    jstring (JNICALL *native_get_version)(JNIEnv *env, jclass cls);
    jlong (JNICALL *native_get_boot_token)(JNIEnv *env, jclass cls);
    jboolean (JNICALL *native_install_boot_material)(JNIEnv *env, jclass cls, jbyteArray material);
    jboolean (JNICALL *native_is_boot_material_ready)(JNIEnv *env, jclass cls);
    void (JNICALL *native_abort_boot_material)(JNIEnv *env, jclass cls);
    void (JNICALL *native_preload_runtime_resources)(JNIEnv *env, jclass cls, jbyteArray preload_index, jbyteArray commitments, jbyteArray startup_nonce);
    jbyteArray (JNICALL *native_derive_class_encryption_key)(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length);
    jbyteArray (JNICALL *native_decrypt_class_bytes)(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jbyteArray nonceArr, jbyteArray ciphertextArr, jbyteArray aadArr, jint keyLength);
    jstring (JNICALL *native_sealed_binding_key)(JNIEnv *env, jclass cls, jbyteArray valueArr);
    jbyteArray (JNICALL *native_decode_runtime_resource)(JNIEnv *env, jclass cls, jbyteArray encoded);
    jobject (JNICALL *execute_vm_resource)(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args);
    jobject (JNICALL *execute_vm_resource_by_token)(JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args);
    void (JNICALL *execute_vm_resource_void)(JNIEnv *env, jclass cls, jlong entryToken);
    jint (JNICALL *execute_vm_resource_int)(JNIEnv *env, jclass cls, jlong entryToken);
    jint (JNICALL *execute_vm_resource_int_int)(JNIEnv *env, jclass cls, jlong entryToken, jint arg0);
    void (JNICALL *execute_vm_resource_int_void)(JNIEnv *env, jclass cls, jlong entryToken, jint arg0);
    jobject (JNICALL *execute_aken_vm_page)(JNIEnv *env, jclass cls, jlong entryToken, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof, jobjectArray args);
    jbyteArray (JNICALL *decode_aken_string_page)(JNIEnv *env, jclass cls, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof);
    jbyteArray (JNICALL *read_aken_class_page)(JNIEnv *env, jclass cls, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof);
    jbyteArray (JNICALL *map_aken_native_chunk)(JNIEnv *env, jclass cls, jbyteArray encodedHandle, jint pageIndex, jbyteArray callSiteProof);
} js_native_abi_table;

JS_EXPORT const js_native_abi_table *js_native_abi_table_v1(void);

#endif
