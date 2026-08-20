#ifndef JS_SHELL_LOADER_H
#define JS_SHELL_LOADER_H

#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include "js_jni_runtime.h"

#ifdef _WIN32
  #define JS_SHELL_EXPORT __declspec(dllexport)
#else
  #define JS_SHELL_EXPORT __attribute__((visibility("default")))
#endif

/*
 * This is public geometry of an already-authenticated, already-validated
 * mapping.  It deliberately carries no payload bytes, keys, nonce material,
 * routes, or artifact binding data.  The shell uses it to avoid re-deriving
 * image/code bounds for every ABI-pointer check while retaining an immutable
 * per-image record that can be checked against the canonical image fields.
 */
#define JS_SHELL_MAPPING_METADATA_VERSION 1u

typedef struct js_shell_mapping_metadata {
    uintptr_t image_low;
    uintptr_t image_high;
    uintptr_t code_low;
    uintptr_t code_high;
    unsigned int mapping_unit_count;
    unsigned int version;
} js_shell_mapping_metadata;

typedef struct js_shell_loaded_image {
    void *image_base;
    size_t image_size;
    void *code_low;
    size_t code_size;
    js_shell_mapping_metadata mapping_metadata;
    void *platform_data;
    jint (*jni_on_load)(JavaVM *vm, void *reserved);
    void (*jni_on_unload)(JavaVM *vm, void *reserved);
    const js_native_abi_table *(*native_abi_table_v1)(void);
} js_shell_loaded_image;

typedef struct js_shell_payload_view {
    const unsigned char *header;
    size_t header_size;
    const unsigned char *payload;
    size_t payload_size;
    const unsigned char *decoded_payload;
    size_t decoded_payload_size;
    const unsigned char *mac;
    size_t mac_size;
    const unsigned char *binding_tag;
    size_t binding_tag_size;
    unsigned int layout_profile;
    unsigned int dispatcher_profile;
} js_shell_payload_view;

int js_shell_load_inner_image(const js_shell_payload_view *payload, js_shell_loaded_image *out_image);
void js_shell_unload_inner_image(js_shell_loaded_image *image);
const char *js_shell_loader_failure_reason(void);

#endif
