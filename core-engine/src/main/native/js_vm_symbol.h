#ifndef JS_VM_SYMBOL_H
#define JS_VM_SYMBOL_H

#include "js_vm_internal.h"

JS_HIDDEN unsigned long long js_vm_hash64_string(const char *value);
JS_HIDDEN js_vm_symbol_cache_entry* js_vm_symbol_cache_lookup(js_vm_program *p, int cp_idx, int kind);
JS_HIDDEN void js_vm_symbol_cache_clear_entry(JNIEnv *env, js_vm_symbol_cache_entry *entry);
JS_HIDDEN js_vm_symbol_cache_entry* js_vm_class_cache_add(JNIEnv *env, js_vm_program *p, int cp_idx, int kind, jclass cls, const char *type_name);
JS_HIDDEN js_vm_symbol_cache_entry* js_vm_symbol_cache_add(JNIEnv *env, js_vm_program *p, int cp_idx, int kind, jclass cls, jmethodID mid, jfieldID fid, unsigned char tag, const js_vm_method_ref *ref, const char *lookup_name, unsigned char ret_tag, unsigned char is_constructor);
JS_HIDDEN int js_vm_resolve_field_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind);
JS_HIDDEN int js_vm_resolve_method_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind, int opcode);
JS_HIDDEN int js_vm_resolve_class_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind);
JS_HIDDEN js_vm_symbol_cache_entry* js_vm_get_cached_class_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind);
JS_HIDDEN int js_vm_prepare_symbol_cache(JNIEnv *env, js_vm_program *p);
JS_HIDDEN void js_vm_clear_decoded_cp(js_vm_cp *cp);
JS_HIDDEN int js_vm_decode_cp_entry(js_vm_program *p, int cp_idx, js_vm_cp *out);
JS_HIDDEN char* js_vm_cp_string_owned(js_vm_program *p, int cp_idx);
JS_HIDDEN char js_vm_return_descriptor_from_meta(js_vm_program *p, jlong expected_token);

JS_HIDDEN void js_vm_free_method_ref(js_vm_method_ref *mr);
JS_HIDDEN char* js_vm_copy_range(const char *start, size_t len);
JS_HIDDEN char* js_vm_copy_cstr_range(const char *start, const char *end);
JS_HIDDEN const char* js_vm_part_end(const char *start);
JS_HIDDEN int js_vm_parse_method_ref(const char *ref, js_vm_method_ref *out);
JS_HIDDEN int js_vm_descriptor_arg_tags(const char *desc, char **tags_out, int *count_out);
JS_HIDDEN char js_vm_descriptor_return_tag(const char *desc);
#endif
