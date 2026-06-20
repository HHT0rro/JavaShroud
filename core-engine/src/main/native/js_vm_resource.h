#ifndef JS_VM_RESOURCE_H
#define JS_VM_RESOURCE_H

#include "js_vm_internal.h"

#define JS_VM_CALL_GATE_KEY_LEN 128

typedef struct {
    jlong entry_token;
    char resource_path[JS_VM_CALL_GATE_KEY_LEN];
    int active;
    int loading;
} js_vm_call_gate_entry;

JS_HIDDEN extern volatile int js_vm_preload_in_progress;
JS_HIDDEN extern char js_vm_last_prepare_stage[96];

JS_HIDDEN void js_vm_free_program(JNIEnv *env, js_vm_program *program);
JS_HIDDEN unsigned char* js_runtime_resource_decode_owned(const unsigned char *raw, int raw_len, int *out_len);
JS_HIDDEN unsigned char* js_vbc4_zstd_decompress_owned(const unsigned char *stored, uint32_t stored_len, uint32_t plain_len);
JS_HIDDEN js_vm_loaded_resource js_vm_load_resource_bytes_with_loader(JNIEnv *env, jclass helper_cls, jstring resourcePath);
JS_HIDDEN jbyteArray js_vm_load_resource_bytes(JNIEnv *env, jclass helper_cls, jstring resourcePath);
JS_HIDDEN jobject js_vm_resource_from_loader(JNIEnv *env, jobject loader, jstring resourcePath);
JS_HIDDEN jobject js_vm_class_resource_as_stream(JNIEnv *env, jobject class_obj, jstring resource_path);
JS_HIDDEN jobject js_vm_context_class_loader(JNIEnv *env);
JS_HIDDEN jobject js_vm_helper_class_loader(JNIEnv *env, jclass helper_cls);
JS_HIDDEN unsigned char* js_vm_decode_resource_path_owned(JNIEnv *env, jclass helper_cls, const char *path, int *out_len);
JS_HIDDEN unsigned char* js_vm_reassemble_sliced_resource(JNIEnv *env, jclass helper_cls, unsigned char *decoded, int decoded_len, int *out_len);
JS_HIDDEN int js_hex32_to_bytes(const char *hex, unsigned char out[32]);
JS_HIDDEN int js_parse_u32_token(const char *text, uint32_t *out);
JS_HIDDEN char* js_next_manifest_field(char **cursor);
JS_HIDDEN void js_vm_register_preload_index_entries(const unsigned char *index_bytes, int index_len);
JS_HIDDEN void js_vm_resource_alias_register(const char *original_path, const char *sealed_path);
JS_HIDDEN const char* js_vm_resource_alias_resolve(const char *path);
JS_HIDDEN void js_vm_call_gate_register(jlong entry_token, const char *resource_path);
JS_HIDDEN const js_vm_call_gate_entry* js_vm_call_gate_lookup(jlong entry_token);
JS_HIDDEN int js_vm_call_gate_mark_loading(jlong entry_token, const char *resource_path);
JS_HIDDEN void js_vm_call_gate_clear_loading(jlong entry_token);
JS_HIDDEN void js_vm_call_gate_reset(void);
JS_HIDDEN js_vm_program* js_vm_prepare_resource_program_bound(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, const char *binding_path_override);
JS_HIDDEN js_vm_program* js_vm_prepare_resource_program(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath);
JS_HIDDEN js_vm_program* js_vm_preload_indexed_program_on_demand(JNIEnv *env, jclass resource_cls, jlong entry_token, const char *resource_path, jstring resourcePath);
JS_HIDDEN jobject js_vm_execute_cached_program(JNIEnv *env, jclass resource_cls, js_vm_program *program, jobjectArray args);
JS_HIDDEN jobject js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args);
JS_HIDDEN jobject js_vm_execute_resource_by_token(JNIEnv *env, jclass resource_cls, jlong entry_token, jobjectArray args);
JS_HIDDEN js_vm_program* js_vm_find_preloaded_program_by_method(unsigned long long class_hash, unsigned long long meth_hash, unsigned long long sig_hash);
JS_HIDDEN js_vm_program* js_vm_ephemeral_cache_get(jlong entry_token, const char *resource_path);
JS_HIDDEN js_vm_program* js_vm_ephemeral_cache_find_by_method(unsigned long long class_hash, unsigned long long meth_hash, unsigned long long sig_hash);
JS_HIDDEN int js_vm_ephemeral_cache_put(jlong entry_token, const char *resource_path, js_vm_program *program);
JS_HIDDEN void js_vm_ephemeral_cache_clear(JNIEnv *env);
JS_HIDDEN void js_vm_cache_lock_init(void);
JS_HIDDEN void js_vm_cache_lock_destroy(void);

#endif
