#ifndef JS_VM_CORE_H
#define JS_VM_CORE_H

#include "js_native_common.h"
#include "js_vm_internal.h"

/* VM core dispatch lives in js_vm_core.c while interpreter diversification
 * still targets that file. */

JS_HIDDEN void js_vm_clear_execution_program(js_vm_program *program);
JS_HIDDEN void js_vm_clear_program_execution_insns(js_vm_program *program);
JS_HIDDEN int js_vm_adopt_validated_execution_program(js_vm_program *program, js_vm_program *validation);
JS_HIDDEN void js_vm_copy_execution_program_header(js_vm_program *dst, js_vm_program *src);
JS_HIDDEN int js_vm_clone_cached_execution_program(js_vm_program *source, js_vm_program *execution);
JS_HIDDEN int js_vm_append_execution_insn(js_vm_program *program, jint opcode, jint op_count, const jint *operands);
JS_HIDDEN int js_vm_append_resident_insn(js_vm_program *p, jint opcode, jint op_count, jint first_operand);
JS_HIDDEN int js_vm_local_perm(int logical, int cap, uint32_t mul, uint32_t add);
JS_HIDDEN js_vm_value js_vm_null_value(void);
JS_HIDDEN js_vm_value js_vm_int_value(jint x);
JS_HIDDEN js_vm_value js_vm_long_value(jlong x);
JS_HIDDEN js_vm_value js_vm_float_value(jfloat x);
JS_HIDDEN js_vm_value js_vm_double_value(jdouble x);
JS_HIDDEN js_vm_value js_vm_object_value(jobject x);
JS_HIDDEN js_vm_value js_vm_uninit_value(int id, const char *type);
JS_HIDDEN void js_vm_clear_value(js_vm_value *v);
JS_HIDDEN void js_vm_clear_value_range(js_vm_value *values, int count);
JS_HIDDEN js_vm_value js_vm_clone_value(js_vm_value v);
JS_HIDDEN int js_vm_stack_has_capacity(int cap, int sp, int needed);
JS_HIDDEN int js_vm_push(js_vm_value *stack, int cap, int *sp, js_vm_value v);
JS_HIDDEN int js_vm_push_copy(js_vm_value *stack, int cap, int *sp, js_vm_value v);
JS_HIDDEN int js_vm_pop(js_vm_value *stack, int *sp, js_vm_value *out);
JS_HIDDEN int js_vm_push_call_result(JNIEnv *env, js_vm_value *stack, int stack_cap, int *sp, char ret_tag, jvalue value);
JS_HIDDEN int js_vm_value_is_null(js_vm_value v);
JS_HIDDEN int js_vm_value_is_wide(js_vm_value v);
JS_HIDDEN int js_vm_original_method_is_instance(js_vm_program *p);
JS_HIDDEN int js_vm_ldc_type_matches_original_owner(const char *type_desc, js_vm_program *p);
JS_HIDDEN extern volatile uint32_t js_vm_trace_poison_seed;
JS_HIDDEN extern volatile int js_vm_last_validation_error;
JS_HIDDEN int js_vm_execute(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret);
JS_HIDDEN int js_vm_execute_register(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret);
JS_HIDDEN js_vm_object_result js_vm_execute_prepared_program(JNIEnv *env, js_vm_program *program, jobjectArray args);
JS_HIDDEN int js_vm_execute_hot_path_self_check(void);
JS_HIDDEN jobject js_vm_get_active_host_loader(void);
JS_HIDDEN void js_vm_set_active_host_loader(jobject loader);
JS_HIDDEN int js_vm_parse_program(const unsigned char *data, int len, js_vm_program *p, const unsigned char *state_binding, int state_binding_len);
JS_HIDDEN int js_vm_build_execution_program_from_registers(js_vm_program *source, js_vm_program *execution);
JS_HIDDEN int js_vm_active_program_push(js_vm_program *program);
JS_HIDDEN void js_vm_active_program_pop(void);
JS_HIDDEN js_vm_program* js_vm_active_program_find_by_method(unsigned long long class_hash, unsigned long long meth_hash, unsigned long long sig_hash);
JS_HIDDEN void js_vm_clear_exception(JNIEnv *env);
JS_HIDDEN jobject js_vm_fail_closed(JNIEnv *env, const char *reason);
JS_HIDDEN int js_vm_build_state_binding(jlong entry_token, const char *resource_path, unsigned char *out, int out_cap);
JS_HIDDEN int js_vm_to_object(js_vm_value v, jobject *out);
JS_HIDDEN int js_vm_to_int(js_vm_value v, jint *out);
JS_HIDDEN int js_vm_to_long(js_vm_value v, jlong *out);
JS_HIDDEN int js_vm_to_float(js_vm_value v, jfloat *out);
JS_HIDDEN int js_vm_to_double(js_vm_value v, jdouble *out);
JS_HIDDEN int js_vm_boxed_arg(JNIEnv *env, jobject obj, js_vm_value *out);
JS_HIDDEN int js_vm_to_jvalue(JNIEnv *env, js_vm_value v, char tag, jvalue *out);
JS_HIDDEN jobject js_vm_box_jvalue_arg(JNIEnv *env, char tag, jvalue value);
JS_HIDDEN jstring js_vm_value_to_string(JNIEnv *env, js_vm_value v);
JS_HIDDEN jstring js_vm_value_to_string_for_tag(JNIEnv *env, js_vm_value v, char tag);
JS_HIDDEN char* js_vm_binary_class_name(const char *class_name);
JS_HIDDEN jclass js_vm_primitive_class(JNIEnv *env, char tag);
JS_HIDDEN jclass js_vm_find_registration_class(JNIEnv *env, const char *class_name);
JS_HIDDEN char* js_lookup_bound_class(JNIEnv *env, const char *original);
JS_HIDDEN char* js_lookup_bound_method(JNIEnv *env, const char *original_class, const char *method_name, const char *signature);
JS_HIDDEN jclass js_vm_find_class_name(JNIEnv *env, const char *name);
JS_HIDDEN jobject js_vm_new_multi_array(JNIEnv *env, const char *descriptor, jint *dimensions, int dim_count);
JS_HIDDEN jobject js_vm_new_throwable(JNIEnv *env, const char *class_name, const char *message);
JS_HIDDEN int js_vm_throw_new(JNIEnv *env, const char *class_name, const char *message);
JS_HIDDEN int js_vm_is_array_object(JNIEnv *env, jobject obj);
JS_HIDDEN jobject js_vm_clone_array(JNIEnv *env, jobject array);
JS_HIDDEN jobject js_vm_new_primitive_array(JNIEnv *env, jint type_code, jint count);
JS_HIDDEN int js_vm_array_load(JNIEnv *env, int opcode, js_vm_value array_value, jint index, js_vm_value *out);
JS_HIDDEN int js_vm_array_store(JNIEnv *env, int opcode, js_vm_value array_value, jint index, js_vm_value value);
JS_HIDDEN int js_vm_read_u1(const unsigned char *data, int len, int *pos, unsigned int *out);
JS_HIDDEN int js_vm_read_u2(const unsigned char *data, int len, int *pos, unsigned int *out);
JS_HIDDEN int js_vm_read_u4(const unsigned char *data, int len, int *pos, uint32_t *out);
JS_HIDDEN int js_vm_read_u8(const unsigned char *data, int len, int *pos, uint64_t *out);
JS_HIDDEN int js_vbc4_decode_block_dispatch_next(int seed, int block_id, int block_count, uint32_t token);
JS_HIDDEN int js_vm_resident_key_mask_from_nonce(const unsigned char nonce[16]);
JS_HIDDEN int js_vm_resident_key_mask(const js_vm_program *p);
JS_HIDDEN void js_vm_init_resident_key_mask(js_vm_program *p, const unsigned char nonce[16]);
JS_HIDDEN void js_vm_store_resident_build_seed(js_vm_program *p, int build_seed);
JS_HIDDEN int js_vm_load_resident_build_seed(const js_vm_program *p);
JS_HIDDEN void js_vm_store_resident_mac_key(js_vm_program *p, int mac_key);
JS_HIDDEN int js_vm_load_resident_mac_key(const js_vm_program *p);
JS_HIDDEN jint js_vm_resident_opcode_mask_epoch(const js_vm_program *p, int index, jint epoch);
JS_HIDDEN jint js_vm_resident_opcode_mask(const js_vm_program *p, int index);
JS_HIDDEN jint js_vm_store_resident_opcode(const js_vm_program *p, int index, jint opcode);
JS_HIDDEN jint js_vm_load_resident_opcode(const js_vm_program *p, int index);
JS_HIDDEN jint js_vm_next_opcode_epoch(const js_vm_program *p, int index, jint old_epoch, int step, int pc_after_fetch, int stack_depth);
JS_HIDDEN void js_vm_rewrap_resident_opcode(js_vm_program *p, int index, jint opcode, int step, int pc_after_fetch, int stack_depth);
JS_HIDDEN void js_vm_rotate_resident_block(js_vm_program *p, int anchor, int step, uint32_t dispatch_drift_state, int pc_after_fetch, int stack_depth);
JS_HIDDEN jint js_vm_resident_operand_mask(const js_vm_program *p, int insn_index, int operand_index);
JS_HIDDEN jint js_vm_store_resident_operand(const js_vm_program *p, int insn_index, int operand_index, jint operand);
JS_HIDDEN jint js_vm_load_resident_operand(const js_vm_program *p, int insn_index, int operand_index);
JS_HIDDEN jint js_vm_resident_exception_mask(const js_vm_program *p, int exception_index, int field_index);
JS_HIDDEN jint js_vm_store_resident_exception_field(const js_vm_program *p, int exception_index, int field_index, jint value);
JS_HIDDEN jint js_vm_load_resident_exception_field(const js_vm_program *p, int exception_index, int field_index, jint value);
JS_HIDDEN js_vm_exception js_vm_load_resident_exception(const js_vm_program *p, int exception_index);
JS_HIDDEN void js_vm_free_program(JNIEnv *env, js_vm_program *p);

#endif
