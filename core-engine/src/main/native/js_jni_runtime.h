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
} js_jni_cache_state;

JS_HIDDEN extern js_jni_cache_state js_jni_cache;
JS_HIDDEN int js_jni_cache_init(JNIEnv *env);
JS_HIDDEN void js_jni_cache_destroy(JNIEnv *env);
JS_HIDDEN jclass js_vm_find_registration_class(JNIEnv *env, const char *class_name);
JS_HIDDEN char* js_lookup_bound_class(JNIEnv *env, const char *original);
JS_HIDDEN char* js_lookup_bound_method(JNIEnv *env, const char *original_class, const char *method_name, const char *signature);
JS_HIDDEN void js_vm_mark_hot_integrity_baseline_clean(void);
JS_HIDDEN void js_runtime_on_unload_cleanup(JNIEnv *env);

#endif
