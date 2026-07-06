#ifndef JS_SHELL_LOADER_H
#define JS_SHELL_LOADER_H

#include <jni.h>
#include <stddef.h>
#include "js_jni_runtime.h"

#ifdef _WIN32
  #define JS_SHELL_EXPORT __declspec(dllexport)
#else
  #define JS_SHELL_EXPORT __attribute__((visibility("default")))
#endif

typedef struct js_shell_loaded_image {
    void *image_base;
    size_t image_size;
    void *code_low;
    size_t code_size;
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
