#include "js_vm_core.h"
#include "js_jni_runtime.h"
#include "js_vm_symbol.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define JS_VM_MAXS 0xFE
#define JS_VM_UNSUPPORTED 0xFF

#if defined(_MSC_VER)
__declspec(thread) static js_vm_program *js_vm_active_program_stack[64];
__declspec(thread) static int js_vm_active_program_depth = 0;
#elif defined(__GNUC__) || defined(__clang__)
__thread static js_vm_program *js_vm_active_program_stack[64];
__thread static int js_vm_active_program_depth = 0;
#else
static js_vm_program *js_vm_active_program_stack[64];
static int js_vm_active_program_depth = 0;
#endif

/* Active host class loader for the currently executing virtualized method.
 * The dispatch entry receives the calling obfuscated class; symbol resolution
 * falls back to this loader for app-classpath-only classes. */
#if defined(_MSC_VER)
__declspec(thread) static jobject js_vm_active_host_loader = NULL;
#elif defined(__GNUC__) || defined(__clang__)
__thread static jobject js_vm_active_host_loader = NULL;
#else
static jobject js_vm_active_host_loader = NULL;
#endif

JS_HIDDEN jobject js_vm_get_active_host_loader(void) { return js_vm_active_host_loader; }

JS_HIDDEN void js_vm_set_active_host_loader(jobject loader) { js_vm_active_host_loader = loader; }

JS_HIDDEN volatile int js_vm_last_parse_stage = 0;

JS_HIDDEN int js_vm_active_program_push(js_vm_program *program) {
    if (!program) return 0;
    if (js_vm_active_program_depth >= (int)(sizeof(js_vm_active_program_stack) / sizeof(js_vm_active_program_stack[0]))) return 0;
    js_vm_active_program_stack[js_vm_active_program_depth++] = program;
    return 1;
}

JS_HIDDEN void js_vm_active_program_pop(void) {
    if (js_vm_active_program_depth > 0) js_vm_active_program_stack[--js_vm_active_program_depth] = NULL;
}

JS_HIDDEN js_vm_program* js_vm_active_program_find_by_method(unsigned long long class_hash, unsigned long long meth_hash, unsigned long long sig_hash) {
    if (class_hash == 0ULL || meth_hash == 0ULL || sig_hash == 0ULL) return NULL;
    for (int i = js_vm_active_program_depth - 1; i >= 0; i--) {
        js_vm_program *program = js_vm_active_program_stack[i];
        if (program && program->original_owner_hash == class_hash &&
            program->original_name_hash == meth_hash &&
            program->original_desc_hash == sig_hash) {
            return program;
        }
    }
    return NULL;
}

JS_HIDDEN int js_vm_execute_register(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret) {
    if (!p) return 0;
    js_vm_program execution;
    memset(&execution, 0, sizeof(execution));
    if (p->cached_execution_ready && p->insns && p->insn_count > 0) {
        if (!js_vm_clone_cached_execution_program(p, &execution)) {
            js_vm_clear_execution_program(&execution);
            return 0;
        }
    } else if (!js_vm_build_execution_program_from_registers(p, &execution)) {
        js_vm_clear_execution_program(&execution);
        return 0;
    }
    int pushed_active_program = js_vm_active_program_push(&execution);
    int ok = js_vm_execute(env, &execution, args, ret_desc, ret);
    if (pushed_active_program) js_vm_active_program_pop();
    /* Execution program owns its per-run symbol cache exclusively. */
    if (execution.symbols) {
        for (int si = 0; si < execution.symbol_count; si++) js_vm_symbol_cache_clear_entry(env, &execution.symbols[si]);
        js_vbc4_wipe_volatile(execution.symbols, (size_t)execution.symbol_count * sizeof(js_vm_symbol_cache_entry));
        free(execution.symbols);
        execution.symbols = NULL;
        execution.symbol_count = 0;
    }
    js_vm_clear_execution_program(&execution);
    return ok;
}

JS_HIDDEN void js_vm_clear_exception(JNIEnv *env) {
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

JS_HIDDEN js_vm_value js_vm_null_value(void) { js_vm_value v; memset(&v, 0, sizeof(v)); v.type = JS_VM_VAL_NULL; return v; }
JS_HIDDEN js_vm_value js_vm_int_value(jint x) { js_vm_value v = js_vm_null_value(); v.type = JS_VM_VAL_INT; v.i = x; return v; }
JS_HIDDEN js_vm_value js_vm_long_value(jlong x) { js_vm_value v = js_vm_null_value(); v.type = JS_VM_VAL_LONG; v.l = x; return v; }
JS_HIDDEN js_vm_value js_vm_float_value(jfloat x) { js_vm_value v = js_vm_null_value(); v.type = JS_VM_VAL_FLOAT; v.f = x; return v; }
JS_HIDDEN js_vm_value js_vm_double_value(jdouble x) { js_vm_value v = js_vm_null_value(); v.type = JS_VM_VAL_DOUBLE; v.d = x; return v; }
JS_HIDDEN js_vm_value js_vm_object_value(jobject x) { js_vm_value v = js_vm_null_value(); if (x) { v.type = JS_VM_VAL_OBJECT; v.o = x; } return v; }
JS_HIDDEN js_vm_value js_vm_uninit_value(int id, const char *type) { js_vm_value v = js_vm_null_value(); v.type = JS_VM_VAL_UNINIT; v.uninit_id = id; v.uninit_type = type; return v; }

JS_HIDDEN void js_vm_clear_value(js_vm_value *v) {
    if (!v) return;
    if (v->type == JS_VM_VAL_UNINIT && v->uninit_type) {
        char *owned_type = (char*)v->uninit_type;
        js_vbc4_wipe_volatile(owned_type, strlen(owned_type));
        free(owned_type);
    }
    memset(v, 0, sizeof(*v));
    v->type = JS_VM_VAL_NULL;
}

JS_HIDDEN void js_vm_clear_value_range(js_vm_value *values, int count) {
    if (!values || count <= 0) return;
    for (int i = 0; i < count; i++) js_vm_clear_value(&values[i]);
}

JS_HIDDEN js_vm_value js_vm_clone_value(js_vm_value v) {
    js_vm_value copy = v;
    if (v.type == JS_VM_VAL_UNINIT && v.uninit_type) {
        size_t len = strlen(v.uninit_type);
        char *owned_type = (char*)malloc(len + 1);
        if (!owned_type) {
            copy.uninit_type = NULL;
            return copy;
        }
        memcpy(owned_type, v.uninit_type, len + 1);
        copy.uninit_type = owned_type;
    }
    return copy;
}

JS_HIDDEN int js_vm_stack_has_capacity(int cap, int sp, int needed) {
    return sp >= 0 && needed >= 0 && sp <= cap && cap - sp >= needed;
}

JS_HIDDEN int js_vm_push(js_vm_value *stack, int cap, int *sp, js_vm_value v) {
    if (!js_vm_stack_has_capacity(cap, *sp, 1)) return 0;
    js_vm_clear_value(&stack[*sp]);
    stack[(*sp)++] = v;
    return 1;
}

JS_HIDDEN int js_vm_push_copy(js_vm_value *stack, int cap, int *sp, js_vm_value v) {
    if (!js_vm_stack_has_capacity(cap, *sp, 1)) return 0;
    js_vm_value copy = js_vm_clone_value(v);
    if (v.type == JS_VM_VAL_UNINIT && v.uninit_type && !copy.uninit_type) return 0;
    return js_vm_push(stack, cap, sp, copy);
}

JS_HIDDEN int js_vm_pop(js_vm_value *stack, int *sp, js_vm_value *out) {
    if (*sp <= 0) return 0;
    *out = stack[--(*sp)];
    memset(&stack[*sp], 0, sizeof(stack[*sp]));
    stack[*sp].type = JS_VM_VAL_NULL;
    return 1;
}

JS_HIDDEN int js_vm_push_call_result(JNIEnv *env, js_vm_value *stack, int stack_cap, int *sp, char ret_tag, jvalue value) {
    switch (ret_tag) {
        case 'V': return 1;
        case 'Z': return js_vm_push(stack, stack_cap, sp, js_vm_int_value(value.z ? 1 : 0));
        case 'B': return js_vm_push(stack, stack_cap, sp, js_vm_int_value((jint)value.b));
        case 'S': return js_vm_push(stack, stack_cap, sp, js_vm_int_value((jint)value.s));
        case 'C': return js_vm_push(stack, stack_cap, sp, js_vm_int_value((jint)value.c));
        case 'I': return js_vm_push(stack, stack_cap, sp, js_vm_int_value(value.i));
        case 'J': return js_vm_push(stack, stack_cap, sp, js_vm_long_value(value.j));
        case 'F': return js_vm_push(stack, stack_cap, sp, js_vm_float_value(value.f));
        case 'D': return js_vm_push(stack, stack_cap, sp, js_vm_double_value(value.d));
        case 'L':
        case '[':
            return js_vm_push(stack, stack_cap, sp, js_vm_object_value(value.l));
        default:
            (void)env;
            return 0;
    }
}

JS_HIDDEN int js_vm_value_is_null(js_vm_value v) { return v.type == JS_VM_VAL_NULL || (v.type == JS_VM_VAL_OBJECT && v.o == NULL); }
JS_HIDDEN int js_vm_value_is_wide(js_vm_value v) { return v.type == JS_VM_VAL_LONG || v.type == JS_VM_VAL_DOUBLE; }

JS_HIDDEN int js_vm_original_method_is_instance(js_vm_program *p) {
    return p && (p->original_access & 0x0008U) == 0;
}

JS_HIDDEN int js_vm_ldc_type_matches_original_owner(const char *type_desc, js_vm_program *p) {
    if (!type_desc || !p || !p->original_owner || !p->original_owner[0]) return 0;
    if (strcmp(type_desc, p->original_owner) == 0) return 1;
    if (type_desc[0] == 'L') {
        const char *semi = strchr(type_desc, ';');
        size_t owner_len = strlen(p->original_owner);
        return semi && (size_t)(semi - type_desc - 1) == owner_len && strncmp(type_desc + 1, p->original_owner, owner_len) == 0;
    }
    return 0;
}

JS_HIDDEN int js_vm_to_object(js_vm_value v, jobject *out) {
    if (v.type == JS_VM_VAL_NULL) { *out = NULL; return 1; }
    if (v.type == JS_VM_VAL_OBJECT) { *out = v.o; return 1; }
    return 0;
}

JS_HIDDEN int js_vm_to_int(js_vm_value v, jint *out) {
    switch (v.type) { case JS_VM_VAL_NULL: *out = 0; return 1; case JS_VM_VAL_INT: *out = v.i; return 1; case JS_VM_VAL_LONG: *out = (jint)v.l; return 1; case JS_VM_VAL_FLOAT: *out = (jint)v.f; return 1; case JS_VM_VAL_DOUBLE: *out = (jint)v.d; return 1; default: return 0; }
}

JS_HIDDEN int js_vm_to_long(js_vm_value v, jlong *out) {
    switch (v.type) { case JS_VM_VAL_NULL: *out = 0; return 1; case JS_VM_VAL_INT: *out = (jlong)v.i; return 1; case JS_VM_VAL_LONG: *out = v.l; return 1; case JS_VM_VAL_FLOAT: *out = (jlong)v.f; return 1; case JS_VM_VAL_DOUBLE: *out = (jlong)v.d; return 1; default: return 0; }
}

JS_HIDDEN int js_vm_to_float(js_vm_value v, jfloat *out) {
    switch (v.type) { case JS_VM_VAL_NULL: *out = 0.0f; return 1; case JS_VM_VAL_INT: *out = (jfloat)v.i; return 1; case JS_VM_VAL_LONG: *out = (jfloat)v.l; return 1; case JS_VM_VAL_FLOAT: *out = v.f; return 1; case JS_VM_VAL_DOUBLE: *out = (jfloat)v.d; return 1; default: return 0; }
}

JS_HIDDEN int js_vm_to_double(js_vm_value v, jdouble *out) {
    switch (v.type) { case JS_VM_VAL_NULL: *out = 0.0; return 1; case JS_VM_VAL_INT: *out = (jdouble)v.i; return 1; case JS_VM_VAL_LONG: *out = (jdouble)v.l; return 1; case JS_VM_VAL_FLOAT: *out = (jdouble)v.f; return 1; case JS_VM_VAL_DOUBLE: *out = v.d; return 1; default: return 0; }
}

JS_HIDDEN int js_vm_boxed_arg(JNIEnv *env, jobject obj, js_vm_value *out) {
    if (!obj) { *out = js_vm_null_value(); return 1; }
    if (!js_jni_cache.initialized) return 0;
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.integer_class)) { *out = js_vm_int_value((*env)->CallIntMethod(env, obj, js_jni_cache.integer_int_value)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.boolean_class)) { *out = js_vm_int_value((*env)->CallBooleanMethod(env, obj, js_jni_cache.boolean_boolean_value) ? 1 : 0); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.byte_class)) { *out = js_vm_int_value((jint)(*env)->CallByteMethod(env, obj, js_jni_cache.byte_byte_value)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.short_class)) { *out = js_vm_int_value((jint)(*env)->CallShortMethod(env, obj, js_jni_cache.short_short_value)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.character_class)) { *out = js_vm_int_value((jint)(*env)->CallCharMethod(env, obj, js_jni_cache.character_char_value)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.long_class)) { *out = js_vm_long_value((*env)->CallLongMethod(env, obj, js_jni_cache.long_long_value)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.float_class)) { *out = js_vm_float_value((*env)->CallFloatMethod(env, obj, js_jni_cache.float_float_value)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.double_class)) { *out = js_vm_double_value((*env)->CallDoubleMethod(env, obj, js_jni_cache.double_double_value)); return !(*env)->ExceptionCheck(env); }
    *out = js_vm_object_value(obj);
    return 1;
}

static int js_vm_to_int_coerced(JNIEnv *env, js_vm_value v, jint *out) {
    if (js_vm_to_int(v, out)) return 1;
    if (v.type == JS_VM_VAL_OBJECT && v.o && js_jni_cache.initialized) {
        js_vm_value unboxed;
        if (js_vm_boxed_arg(env, v.o, &unboxed) && unboxed.type != JS_VM_VAL_OBJECT) {
            int ok = js_vm_to_int(unboxed, out);
            js_vm_clear_value(&unboxed);
            return ok;
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
    return 0;
}

static int js_vm_to_long_coerced(JNIEnv *env, js_vm_value v, jlong *out) {
    if (js_vm_to_long(v, out)) return 1;
    if (v.type == JS_VM_VAL_OBJECT && v.o && js_jni_cache.initialized) {
        js_vm_value unboxed;
        if (js_vm_boxed_arg(env, v.o, &unboxed) && unboxed.type != JS_VM_VAL_OBJECT) {
            int ok = js_vm_to_long(unboxed, out);
            js_vm_clear_value(&unboxed);
            return ok;
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
    return 0;
}

static int js_vm_to_float_coerced(JNIEnv *env, js_vm_value v, jfloat *out) {
    if (js_vm_to_float(v, out)) return 1;
    if (v.type == JS_VM_VAL_OBJECT && v.o && js_jni_cache.initialized) {
        js_vm_value unboxed;
        if (js_vm_boxed_arg(env, v.o, &unboxed) && unboxed.type != JS_VM_VAL_OBJECT) {
            int ok = js_vm_to_float(unboxed, out);
            js_vm_clear_value(&unboxed);
            return ok;
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
    return 0;
}

static int js_vm_to_double_coerced(JNIEnv *env, js_vm_value v, jdouble *out) {
    if (js_vm_to_double(v, out)) return 1;
    if (v.type == JS_VM_VAL_OBJECT && v.o && js_jni_cache.initialized) {
        js_vm_value unboxed;
        if (js_vm_boxed_arg(env, v.o, &unboxed) && unboxed.type != JS_VM_VAL_OBJECT) {
            int ok = js_vm_to_double(unboxed, out);
            js_vm_clear_value(&unboxed);
            return ok;
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
    return 0;
}

JS_HIDDEN int js_vm_to_jvalue(JNIEnv *env, js_vm_value v, char tag, jvalue *out) {
    jint i = 0;
    jlong l = 0;
    jfloat f = 0.0f;
    jdouble d = 0.0;
    memset(out, 0, sizeof(*out));
    switch (tag) {
        case 'Z': if (!js_vm_to_int_coerced(env, v, &i)) return 0; out->z = (jboolean)(i != 0); return 1;
        case 'B': if (!js_vm_to_int_coerced(env, v, &i)) return 0; out->b = (jbyte)i; return 1;
        case 'S': if (!js_vm_to_int_coerced(env, v, &i)) return 0; out->s = (jshort)i; return 1;
        case 'C': if (!js_vm_to_int_coerced(env, v, &i)) return 0; out->c = (jchar)i; return 1;
        case 'I': if (!js_vm_to_int_coerced(env, v, &i)) return 0; out->i = i; return 1;
        case 'J': if (!js_vm_to_long_coerced(env, v, &l)) return 0; out->j = l; return 1;
        case 'F': if (!js_vm_to_float_coerced(env, v, &f)) return 0; out->f = f; return 1;
        case 'D': if (!js_vm_to_double_coerced(env, v, &d)) return 0; out->d = d; return 1;
        case 'L':
        case '[':
            if (v.type == JS_VM_VAL_NULL) { out->l = NULL; return 1; }
            if (v.type == JS_VM_VAL_OBJECT) { out->l = v.o; return 1; }
            return 0;
        default:
            return 0;
    }
}

JS_HIDDEN jobject js_vm_box_jvalue_arg(JNIEnv *env, char tag, jvalue value) {
    if (!js_jni_cache.initialized) return NULL;
    switch (tag) {
        case 'Z': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.boolean_class, js_jni_cache.boolean_value_of, &value);
        case 'B': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.byte_class, js_jni_cache.byte_value_of, &value);
        case 'S': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.short_class, js_jni_cache.short_value_of, &value);
        case 'C': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.character_class, js_jni_cache.character_value_of, &value);
        case 'I': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.integer_class, js_jni_cache.integer_value_of, &value);
        case 'J': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.long_class, js_jni_cache.long_value_of, &value);
        case 'F': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.float_class, js_jni_cache.float_value_of, &value);
        case 'D': return (*env)->CallStaticObjectMethodA(env, js_jni_cache.double_class, js_jni_cache.double_value_of, &value);
        case 'L':
        case '[':
            return value.l ? (*env)->NewLocalRef(env, value.l) : NULL;
        default:
            return NULL;
    }
}

JS_HIDDEN jstring js_vm_value_to_string(JNIEnv *env, js_vm_value v) {
    if (!js_jni_cache.initialized || !js_jni_cache.string_class) return NULL;
    jmethodID mid = NULL;
    jvalue arg;
    memset(&arg, 0, sizeof(arg));
    switch (v.type) {
        case JS_VM_VAL_INT: arg.i = v.i; mid = js_jni_cache.string_value_of_int; break;
        case JS_VM_VAL_LONG: arg.j = v.l; mid = js_jni_cache.string_value_of_long; break;
        case JS_VM_VAL_FLOAT: arg.f = v.f; mid = js_jni_cache.string_value_of_float; break;
        case JS_VM_VAL_DOUBLE: arg.d = v.d; mid = js_jni_cache.string_value_of_double; break;
        case JS_VM_VAL_NULL: arg.l = NULL; mid = js_jni_cache.string_value_of_object; break;
        case JS_VM_VAL_OBJECT: arg.l = v.o; mid = js_jni_cache.string_value_of_object; break;
        default: return (*env)->NewStringUTF(env, "<vm-value>");
    }
    return mid ? (jstring)(*env)->CallStaticObjectMethodA(env, js_jni_cache.string_class, mid, &arg) : NULL;
}

JS_HIDDEN jstring js_vm_value_to_string_for_tag(JNIEnv *env, js_vm_value v, char tag) {
    if (!js_jni_cache.initialized || !js_jni_cache.string_class) return NULL;
    jvalue arg;
    jint i = 0;
    memset(&arg, 0, sizeof(arg));
    switch (tag) {
        case 'Z':
            if (!js_vm_to_int(v, &i)) return NULL;
            arg.z = (jboolean)(i != 0);
            return js_jni_cache.string_value_of_boolean ? (jstring)(*env)->CallStaticObjectMethodA(env, js_jni_cache.string_class, js_jni_cache.string_value_of_boolean, &arg) : NULL;
        case 'C':
            if (!js_vm_to_int(v, &i)) return NULL;
            arg.c = (jchar)i;
            return js_jni_cache.string_value_of_char ? (jstring)(*env)->CallStaticObjectMethodA(env, js_jni_cache.string_class, js_jni_cache.string_value_of_char, &arg) : NULL;
        default:
            return js_vm_value_to_string(env, v);
    }
}

JS_HIDDEN char* js_vm_binary_class_name(const char *class_name) {
    if (!class_name || !class_name[0]) return NULL;
    char *binary_name = js_strdup(class_name);
    if (!binary_name) return NULL;
    for (char *cursor = binary_name; *cursor; cursor++) {
        if (*cursor == '/') *cursor = '.';
    }
    return binary_name;
}

JS_HIDDEN jclass js_vm_primitive_class(JNIEnv *env, char tag) {
    if (!js_jni_cache.initialized) return NULL;
    jfieldID type_field = NULL;
    jclass wrapper = NULL;
    switch (tag) {
        case 'Z': wrapper = js_jni_cache.boolean_class; type_field = js_jni_cache.boolean_type_field; break;
        case 'B': wrapper = js_jni_cache.byte_class; type_field = js_jni_cache.byte_type_field; break;
        case 'S': wrapper = js_jni_cache.short_class; type_field = js_jni_cache.short_type_field; break;
        case 'C': wrapper = js_jni_cache.character_class; type_field = js_jni_cache.character_type_field; break;
        case 'I': wrapper = js_jni_cache.integer_class; type_field = js_jni_cache.integer_type_field; break;
        case 'J': wrapper = js_jni_cache.long_class; type_field = js_jni_cache.long_type_field; break;
        case 'F': wrapper = js_jni_cache.float_class; type_field = js_jni_cache.float_type_field; break;
        case 'D': wrapper = js_jni_cache.double_class; type_field = js_jni_cache.double_type_field; break;
        case 'V': wrapper = js_jni_cache.void_class; type_field = js_jni_cache.void_type_field; break;
        default: return NULL;
    }
    if (!wrapper || !type_field) return NULL;
    return (jclass)(*env)->GetStaticObjectField(env, wrapper, type_field);
}

JS_HIDDEN jclass js_vm_find_class_name(JNIEnv *env, const char *name) {
    if (!name || !*name) return NULL;
    if (name[0] == '[') return (*env)->FindClass(env, name);
    if (name[0] == 'L' && strchr(name, ';')) {
        const char *semi = strchr(name, ';');
        char *internal = js_vm_copy_cstr_range(name + 1, semi);
        if (!internal) return NULL;
        char *mapped = js_lookup_bound_class(env, internal);
        const char *target = mapped && mapped[0] ? mapped : internal;
        jclass cls = js_vm_find_registration_class(env, target);
        free(mapped);
        free(internal);
        return cls;
    }
    if (name[1] == 0) return js_vm_primitive_class(env, name[0]);
    char *mapped = js_lookup_bound_class(env, name);
    const char *target = mapped && mapped[0] ? mapped : name;
    jclass cls = js_vm_find_registration_class(env, target);
    free(mapped);
    return cls;
}

static jclass js_vm_multianew_component_class(JNIEnv *env, const char *descriptor, int dimensions) {
    if (!descriptor || dimensions <= 0) return NULL;
    const char *p = descriptor;
    int consumed = 0;
    while (*p == '[' && consumed < dimensions) { p++; consumed++; }
    return js_vm_find_class_name(env, p);
}

JS_HIDDEN jobject js_vm_new_multi_array(JNIEnv *env, const char *descriptor, jint *dimensions, int dim_count) {
    if (!descriptor || !dimensions || dim_count <= 0) return NULL;
    jclass component = js_vm_multianew_component_class(env, descriptor, dim_count);
    if ((*env)->ExceptionCheck(env) || !component) return NULL;
    jintArray dim_array = (*env)->NewIntArray(env, dim_count);
    if ((*env)->ExceptionCheck(env) || !dim_array) return NULL;
    (*env)->SetIntArrayRegion(env, dim_array, 0, dim_count, dimensions);
    if ((*env)->ExceptionCheck(env)) return NULL;
    if (!js_jni_cache.initialized || !js_jni_cache.reflect_array_class || !js_jni_cache.reflect_array_new_instance_dims) return NULL;
    return (*env)->CallStaticObjectMethod(env, js_jni_cache.reflect_array_class, js_jni_cache.reflect_array_new_instance_dims, component, dim_array);
}

JS_HIDDEN jobject js_vm_new_throwable(JNIEnv *env, const char *class_name, const char *message) {
    jclass cls = NULL;
    jmethodID init = NULL;
    if (js_jni_cache.initialized && class_name && strcmp(class_name, "java/lang/RuntimeException") == 0) {
        cls = js_jni_cache.runtime_exception_class;
        init = js_jni_cache.runtime_exception_init;
    }
    if (!cls && class_name) cls = (*env)->FindClass(env, class_name);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); cls = NULL; }
    if (!cls) {
        cls = js_jni_cache.initialized ? js_jni_cache.runtime_exception_class : (*env)->FindClass(env, "java/lang/RuntimeException");
        init = js_jni_cache.initialized ? js_jni_cache.runtime_exception_init : NULL;
    }
    if (cls && !init) init = (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;)V");
    if ((*env)->ExceptionCheck(env) || !cls || !init) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    jstring msg = (*env)->NewStringUTF(env, message ? message : "VM execution error");
    if ((*env)->ExceptionCheck(env)) return NULL;
    return (*env)->NewObject(env, cls, init, msg);
}

JS_HIDDEN int js_vm_throw_new(JNIEnv *env, const char *class_name, const char *message) {
    jobject ex = js_vm_new_throwable(env, class_name, message);
    if (ex) (*env)->Throw(env, (jthrowable)ex);
    return 0;
}
JS_HIDDEN int js_vm_is_array_object(JNIEnv *env, jobject obj) {
    if (!obj) return 0;
    jclass obj_cls = (*env)->GetObjectClass(env, obj);
    if ((*env)->ExceptionCheck(env) || !obj_cls) return 0;
    if (!js_jni_cache.initialized || !js_jni_cache.class_is_array) return 0;
    return (*env)->CallBooleanMethod(env, obj_cls, js_jni_cache.class_is_array) == JNI_TRUE;
}

JS_HIDDEN jobject js_vm_clone_array(JNIEnv *env, jobject array) {
    if (!array) return NULL;
    jsize len = (*env)->GetArrayLength(env, (jarray)array);
    if ((*env)->ExceptionCheck(env)) return NULL;
    jclass obj_cls = (*env)->GetObjectClass(env, array);
    if ((*env)->ExceptionCheck(env) || !obj_cls) return NULL;
    if (!js_jni_cache.initialized || !js_jni_cache.class_get_component_type) return NULL;
    jclass component = (jclass)(*env)->CallObjectMethod(env, obj_cls, js_jni_cache.class_get_component_type);
    if ((*env)->ExceptionCheck(env) || !component) return NULL;
    jint dim = len;
    if (!js_jni_cache.initialized || !js_jni_cache.reflect_array_new_instance_len) return NULL;
    jobject clone = (*env)->CallStaticObjectMethod(env, js_jni_cache.reflect_array_class, js_jni_cache.reflect_array_new_instance_len, component, dim);
    if ((*env)->ExceptionCheck(env) || !clone) return NULL;
    if (!js_jni_cache.initialized || !js_jni_cache.system_arraycopy) return NULL;
    (*env)->CallStaticVoidMethod(env, js_jni_cache.system_class, js_jni_cache.system_arraycopy, array, 0, clone, 0, len);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return clone;
}

JS_HIDDEN int js_vm_array_load(JNIEnv *env, int opcode, js_vm_value array_value, jint index, js_vm_value *out) {
    if (array_value.type != JS_VM_VAL_OBJECT || !array_value.o) return js_vm_throw_new(env, "java/lang/NullPointerException", "array load on null");
    switch (opcode) {
        case JS_VM_IALOAD: { jint v = 0; (*env)->GetIntArrayRegion(env, (jintArray)array_value.o, index, 1, &v); *out = js_vm_int_value(v); return !(*env)->ExceptionCheck(env); }
        case JS_VM_LALOAD: { jlong v = 0; (*env)->GetLongArrayRegion(env, (jlongArray)array_value.o, index, 1, &v); *out = js_vm_long_value(v); return !(*env)->ExceptionCheck(env); }
        case JS_VM_FALOAD: { jfloat v = 0; (*env)->GetFloatArrayRegion(env, (jfloatArray)array_value.o, index, 1, &v); *out = js_vm_float_value(v); return !(*env)->ExceptionCheck(env); }
        case JS_VM_DALOAD: { jdouble v = 0; (*env)->GetDoubleArrayRegion(env, (jdoubleArray)array_value.o, index, 1, &v); *out = js_vm_double_value(v); return !(*env)->ExceptionCheck(env); }
        case JS_VM_AALOAD: { jobject v = (*env)->GetObjectArrayElement(env, (jobjectArray)array_value.o, index); *out = js_vm_object_value(v); return !(*env)->ExceptionCheck(env); }
        case JS_VM_BALOAD: {
            jclass bool_arr = (*env)->FindClass(env, "[Z");
            if (bool_arr && (*env)->IsInstanceOf(env, array_value.o, bool_arr)) { jboolean v = 0; (*env)->GetBooleanArrayRegion(env, (jbooleanArray)array_value.o, index, 1, &v); *out = js_vm_int_value(v ? 1 : 0); }
            else { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); jbyte v = 0; (*env)->GetByteArrayRegion(env, (jbyteArray)array_value.o, index, 1, &v); *out = js_vm_int_value((jint)v); }
            return !(*env)->ExceptionCheck(env);
        }
        case JS_VM_CALOAD: { jchar v = 0; (*env)->GetCharArrayRegion(env, (jcharArray)array_value.o, index, 1, &v); *out = js_vm_int_value((jint)v); return !(*env)->ExceptionCheck(env); }
        case JS_VM_SALOAD: { jshort v = 0; (*env)->GetShortArrayRegion(env, (jshortArray)array_value.o, index, 1, &v); *out = js_vm_int_value((jint)v); return !(*env)->ExceptionCheck(env); }
        default: return 0;
    }
}

JS_HIDDEN int js_vm_array_store(JNIEnv *env, int opcode, js_vm_value array_value, jint index, js_vm_value value) {
    jint i = 0; jlong l = 0; jfloat f = 0.0f; jdouble d = 0.0;
    if (array_value.type != JS_VM_VAL_OBJECT || !array_value.o) return js_vm_throw_new(env, "java/lang/NullPointerException", "array store on null");
    switch (opcode) {
        case JS_VM_IASTORE: if (!js_vm_to_int(value, &i)) return 0; (*env)->SetIntArrayRegion(env, (jintArray)array_value.o, index, 1, &i); break;
        case JS_VM_LASTORE: if (!js_vm_to_long(value, &l)) return 0; (*env)->SetLongArrayRegion(env, (jlongArray)array_value.o, index, 1, &l); break;
        case JS_VM_FASTORE: if (!js_vm_to_float(value, &f)) return 0; (*env)->SetFloatArrayRegion(env, (jfloatArray)array_value.o, index, 1, &f); break;
        case JS_VM_DASTORE: if (!js_vm_to_double(value, &d)) return 0; (*env)->SetDoubleArrayRegion(env, (jdoubleArray)array_value.o, index, 1, &d); break;
        case JS_VM_AASTORE: {
            jobject obj = NULL;
            if (value.type == JS_VM_VAL_OBJECT) obj = value.o;
            else if (value.type != JS_VM_VAL_NULL) return 0;
            (*env)->SetObjectArrayElement(env, (jobjectArray)array_value.o, index, obj);
            break;
        }
        case JS_VM_BASTORE: {
            if (!js_vm_to_int(value, &i)) return 0;
            jclass bool_arr = (*env)->FindClass(env, "[Z");
            if (bool_arr && (*env)->IsInstanceOf(env, array_value.o, bool_arr)) { jboolean v = (i != 0); (*env)->SetBooleanArrayRegion(env, (jbooleanArray)array_value.o, index, 1, &v); }
            else { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); jbyte v = (jbyte)i; (*env)->SetByteArrayRegion(env, (jbyteArray)array_value.o, index, 1, &v); }
            break;
        }
        case JS_VM_CASTORE: if (!js_vm_to_int(value, &i)) return 0; { jchar v = (jchar)i; (*env)->SetCharArrayRegion(env, (jcharArray)array_value.o, index, 1, &v); } break;
        case JS_VM_SASTORE: if (!js_vm_to_int(value, &i)) return 0; { jshort v = (jshort)i; (*env)->SetShortArrayRegion(env, (jshortArray)array_value.o, index, 1, &v); } break;
        default: return 0;
    }
    return !(*env)->ExceptionCheck(env);
}
JS_HIDDEN jobject js_vm_new_primitive_array(JNIEnv *env, jint type_code, jint count) {
    switch (type_code) {
        case 4: return (jobject)(*env)->NewBooleanArray(env, count);
        case 5: return (jobject)(*env)->NewCharArray(env, count);
        case 6: return (jobject)(*env)->NewFloatArray(env, count);
        case 7: return (jobject)(*env)->NewDoubleArray(env, count);
        case 8: return (jobject)(*env)->NewByteArray(env, count);
        case 9: return (jobject)(*env)->NewShortArray(env, count);
        case 10: return (jobject)(*env)->NewIntArray(env, count);
        case 11: return (jobject)(*env)->NewLongArray(env, count);
        default: return NULL;
    }
}
JS_HIDDEN int js_vm_read_u1(const unsigned char *data, int len, int *pos, unsigned int *out) { if (*pos + 1 > len) return 0; *out = data[*pos]; *pos += 1; return 1; }
JS_HIDDEN int js_vm_read_u2(const unsigned char *data, int len, int *pos, unsigned int *out) { if (*pos + 2 > len) return 0; *out = ((unsigned int)data[*pos] << 8) | (unsigned int)data[*pos + 1]; *pos += 2; return 1; }
JS_HIDDEN int js_vm_read_u4(const unsigned char *data, int len, int *pos, uint32_t *out) { if (*pos + 4 > len) return 0; *out = ((uint32_t)data[*pos] << 24) | ((uint32_t)data[*pos + 1] << 16) | ((uint32_t)data[*pos + 2] << 8) | (uint32_t)data[*pos + 3]; *pos += 4; return 1; }
JS_HIDDEN int js_vm_read_u8(const unsigned char *data, int len, int *pos, uint64_t *out) { uint32_t hi = 0, lo = 0; if (!js_vm_read_u4(data, len, pos, &hi)) return 0; if (!js_vm_read_u4(data, len, pos, &lo)) return 0; *out = ((uint64_t)hi << 32) | (uint64_t)lo; return 1; }

JS_HIDDEN void js_vm_clear_execution_program(js_vm_program *program) {
    if (!program) return;
    if (program->insns) {
        if (!program->borrowed_insn_operands) {
            for (int i = 0; i < program->insn_count; i++) {
                if (program->insns[i].ops) {
                    js_vbc4_wipe_volatile(program->insns[i].ops, (size_t)program->insns[i].op_count * sizeof(jint));
                    free(program->insns[i].ops);
                }
            }
        }
        if (!program->borrowed_insns) js_vbc4_wipe_volatile(program->insns, (size_t)program->insn_count * sizeof(js_vm_insn));
        free(program->insns);
    }
    program->cp = NULL;
    program->exceptions = NULL;
    program->symbols = NULL;
    program->reg_program.insns = NULL;
    js_vbc4_wipe_volatile(program, sizeof(*program));
}

JS_HIDDEN void js_vm_copy_execution_program_header(js_vm_program *dst, js_vm_program *src) {
    memset(dst, 0, sizeof(*dst));
    dst->cp = src->cp;
    dst->cp_count = src->cp_count;
    dst->exceptions = src->exceptions;
    dst->exception_count = src->exception_count;
    dst->max_stack = src->max_stack > 0 ? src->max_stack : 1;
    dst->max_locals = src->max_locals > 0 ? src->max_locals : 1;
    dst->mac_key = src->mac_key;
    dst->build_seed = src->build_seed;
    dst->key_mask = src->key_mask;
    memcpy(dst->nonce, src->nonce, sizeof(dst->nonce));
    dst->metadata_cp_index = src->metadata_cp_index;
    dst->method_local_profile = src->method_local_profile;
    dst->vbc4_flags = src->vbc4_flags;
    dst->nested_vm_profile = src->nested_vm_profile;
    dst->entry_token = src->entry_token;
    dst->return_desc = src->return_desc;
    dst->original_owner = src->original_owner;
    dst->original_name = src->original_name;
    dst->original_desc = src->original_desc;
    dst->original_owner_hash = src->original_owner_hash;
    dst->original_name_hash = src->original_name_hash;
    dst->original_desc_hash = src->original_desc_hash;
    dst->original_access = src->original_access;
    dst->symbols = NULL;
    dst->symbol_count = 0;
}

JS_HIDDEN void js_vm_clear_program_execution_insns(js_vm_program *program) {
    if (!program || !program->insns) return;
    if (!program->borrowed_insn_operands) {
        for (int i = 0; i < program->insn_count; i++) {
            if (program->insns[i].ops) {
                js_vbc4_wipe_volatile(program->insns[i].ops, (size_t)program->insns[i].op_count * sizeof(jint));
                free(program->insns[i].ops);
            }
        }
    }
    if (!program->borrowed_insns) js_vbc4_wipe_volatile(program->insns, (size_t)program->insn_count * sizeof(js_vm_insn));
    free(program->insns);
    program->insns = NULL;
    program->insn_count = 0;
    program->borrowed_insns = 0;
    program->borrowed_insn_operands = 0;
    program->cached_execution_ready = 0;
}

JS_HIDDEN int js_vm_adopt_validated_execution_program(js_vm_program *program, js_vm_program *validation) {
    if (!program || !validation || !validation->insns || validation->insn_count <= 0) return 0;
    js_vm_clear_program_execution_insns(program);
    program->insns = validation->insns;
    program->insn_count = validation->insn_count;
    program->borrowed_insns = validation->borrowed_insns;
    program->borrowed_insn_operands = validation->borrowed_insn_operands;
    program->cached_execution_ready = 1;
    program->max_stack = validation->max_stack > 0 ? validation->max_stack : 1;
    program->max_locals = validation->max_locals > 0 ? validation->max_locals : 1;
    validation->insns = NULL;
    validation->insn_count = 0;
    validation->borrowed_insns = 0;
    validation->borrowed_insn_operands = 0;
    validation->cached_execution_ready = 0;
    return 1;
}

JS_HIDDEN int js_vm_clone_cached_execution_program(js_vm_program *source, js_vm_program *execution) {
    if (!source || !execution || !source->cached_execution_ready || !source->insns || source->insn_count <= 0) return 0;
    js_vm_copy_execution_program_header(execution, source);
    execution->insns = (js_vm_insn*)calloc((size_t)source->insn_count, sizeof(js_vm_insn));
    if (!execution->insns) return 0;
    memcpy(execution->insns, source->insns, (size_t)source->insn_count * sizeof(js_vm_insn));
    execution->insn_count = source->insn_count;
    execution->borrowed_insn_operands = 1;
    return 1;
}

JS_HIDDEN int js_vm_append_execution_insn(js_vm_program *program, jint opcode, jint op_count, const jint *operands) {
    if (!program || op_count < 0 || (op_count > 0 && !operands)) return 0;
    js_vm_insn *grown = (js_vm_insn*)realloc(program->insns, (size_t)(program->insn_count + 1) * sizeof(js_vm_insn));
    if (!grown) return 0;
    program->insns = grown;
    js_vm_insn *slot = &program->insns[program->insn_count];
    memset(slot, 0, sizeof(*slot));
    slot->opcode = js_vm_store_resident_opcode(program, program->insn_count, opcode);
    slot->op_count = op_count;
    if (op_count > 0) {
        slot->ops = (jint*)calloc((size_t)op_count, sizeof(jint));
        if (!slot->ops) return 0;
        for (int i = 0; i < op_count; i++) slot->ops[i] = js_vm_store_resident_operand(program, program->insn_count, i, operands[i]);
    }
    if (opcode == JS_VM_MAXS && op_count >= 2) {
        program->max_stack = operands[0] > 0 ? operands[0] : 1;
        program->max_locals = operands[1] > 0 ? operands[1] : 1;
    }
    program->insn_count++;
    return 1;
}

JS_HIDDEN int js_vm_append_resident_insn(js_vm_program *p, jint opcode, jint op_count, jint first_operand) {
    if (!p) return 0;
    js_vm_insn *grown = (js_vm_insn*)realloc(p->insns, (size_t)(p->insn_count + 1) * sizeof(js_vm_insn));
    if (!grown) return 0;
    p->insns = grown;
    memset(&p->insns[p->insn_count], 0, sizeof(js_vm_insn));
    p->insns[p->insn_count].opcode = js_vm_store_resident_opcode(p, p->insn_count, opcode);
    p->insns[p->insn_count].op_count = op_count;
    if (op_count > 0) {
        p->insns[p->insn_count].ops = (jint*)calloc((size_t)op_count, sizeof(jint));
        if (!p->insns[p->insn_count].ops) return 0;
        p->insns[p->insn_count].ops[0] = js_vm_store_resident_operand(p, p->insn_count, 0, first_operand);
    }
    if (opcode == JS_VM_MAXS && p->insns[p->insn_count].op_count >= 2) {
        jint decoded_max_stack = js_vm_load_resident_operand(p, p->insn_count, 0);
        jint decoded_max_locals = js_vm_load_resident_operand(p, p->insn_count, 1);
        p->max_stack = decoded_max_stack > 0 ? decoded_max_stack : 1;
        p->max_locals = decoded_max_locals > 0 ? decoded_max_locals : 1;
    }
    p->insn_count++;
    return 1;
}

JS_HIDDEN int js_vm_local_perm(int logical, int cap, uint32_t mul, uint32_t add) {
    if (cap <= 1) return 0;
    if (logical < 0 || logical >= cap) return logical;
    uint64_t mapped = ((uint64_t)(uint32_t)logical * (uint64_t)mul + (uint64_t)add) % (uint64_t)(uint32_t)cap;
    return (int)mapped;
}

static uint32_t js_vbc4_rotl32_core(uint32_t value, int bits) { int sh = bits & 31; return sh == 0 ? value : (value << sh) | (value >> (32 - sh)); }

JS_HIDDEN int js_vbc4_decode_block_dispatch_next(int seed, int block_id, int block_count, uint32_t token) {
    uint32_t mask = js_vbc4_rotl32_core((uint32_t)seed, (block_id * 5 + 7) & 31) ^
                    ((uint32_t)block_id * 0x045D9F3Bu) ^
                    ((uint32_t)block_count * 0x119DE1F3u);
    uint32_t payload = token ^ mask;
    uint32_t next_id = payload & 0xFFFFu;
    uint32_t state = (payload >> 16) & 0xFFFFu;
    if (next_id > (uint32_t)block_count) return -1;
    uint32_t mixed = js_vbc4_rotl32_core((uint32_t)seed, (block_id * 3 + 11) & 31) ^
                     ((uint32_t)block_id * 0x632BE59Bu) ^
                     (next_id * 0x85157AF5u) ^
                     ((uint32_t)block_count * 0x9E3779B9u);
    uint32_t expected = (mixed ^ (mixed >> 16)) & 0xFFFFu;
    if (expected == 0u) expected = 1u;
    return state == expected ? (int)next_id : -1;
}

JS_HIDDEN int js_vm_resident_key_mask_from_nonce(const unsigned char nonce[16]) {
    uint32_t x = 0xA5C3E21Fu;
    if (nonce) {
        for (int i = 0; i < 16; i++) {
            x ^= (uint32_t)nonce[i] << ((i & 3) * 8);
            x *= 0x45D9F3Bu;
            x ^= x >> 16;
        }
    }
    x ^= x >> 15;
    x *= 0x7FEB352Du;
    x ^= x >> 16;
    return (int)x;
}

JS_HIDDEN int js_vm_resident_key_mask(const js_vm_program *p) {
    if (!p) return 0;
    return p->key_mask ^ js_vm_resident_key_mask_from_nonce(p->nonce);
}

JS_HIDDEN void js_vm_init_resident_key_mask(js_vm_program *p, const unsigned char nonce[16]) {
    if (!p) return;
    p->key_mask = js_vm_resident_key_mask_from_nonce(nonce) ^ 0x6A09E667;
}

JS_HIDDEN void js_vm_store_resident_build_seed(js_vm_program *p, int build_seed) {
    if (!p) return;
    p->build_seed = build_seed ^ js_vm_resident_key_mask(p);
}

JS_HIDDEN int js_vm_load_resident_build_seed(const js_vm_program *p) {
    return p ? (p->build_seed ^ js_vm_resident_key_mask(p)) : 0;
}

JS_HIDDEN void js_vm_store_resident_mac_key(js_vm_program *p, int mac_key) {
    if (!p) return;
    uint32_t mask = (uint32_t)js_vm_resident_key_mask(p);
    p->mac_key = (int)(((uint32_t)mac_key) ^ js_vbc4_rotl32_core(mask, 7));
}

JS_HIDDEN int js_vm_load_resident_mac_key(const js_vm_program *p) {
    if (!p) return 0;
    uint32_t mask = (uint32_t)js_vm_resident_key_mask(p);
    return (int)(((uint32_t)p->mac_key) ^ js_vbc4_rotl32_core(mask, 7));
}

JS_HIDDEN jint js_vm_resident_opcode_mask_epoch(const js_vm_program *p, int index, jint epoch) {
    uint32_t x = (uint32_t)js_vm_load_resident_mac_key(p) ^ (uint32_t)js_vm_load_resident_build_seed(p) ^ (uint32_t)(index * 0x45D9F3Bu);
    x ^= (uint32_t)epoch * 0x9E3779B1u;
    x ^= p ? js_vbc4_rotl32_core(p->resident_rotation_epoch, (index + 11) & 31) : 0u;
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    return (jint)(x & 0xFFu);
}

JS_HIDDEN jint js_vm_resident_opcode_mask(const js_vm_program *p, int index) {
    return js_vm_resident_opcode_mask_epoch(p, index, p && index >= 0 && index < p->insn_count ? p->insns[index].opcode_epoch : 0);
}

JS_HIDDEN jint js_vm_store_resident_opcode(const js_vm_program *p, int index, jint opcode) {
    return opcode ^ js_vm_resident_opcode_mask(p, index);
}

JS_HIDDEN jint js_vm_load_resident_opcode(const js_vm_program *p, int index) {
    if (!p || index < 0 || index >= p->insn_count) return JS_VM_UNSUPPORTED;
    return p->insns[index].opcode ^ js_vm_resident_opcode_mask(p, index);
}

JS_HIDDEN jint js_vm_next_opcode_epoch(const js_vm_program *p, int index, jint old_epoch, int step, int pc_after_fetch, int stack_depth) {
    uint32_t x = (uint32_t)old_epoch ^ (uint32_t)js_vm_load_resident_build_seed(p) ^ ((uint32_t)js_vm_load_resident_mac_key(p) << 1);
    x ^= (uint32_t)(index * 0x27D4EB2Du) ^ (uint32_t)(step * 0x165667B1u) ^ (uint32_t)(pc_after_fetch * 0x85EBCA77u) ^ (uint32_t)(stack_depth * 0xC2B2AE3Du);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return (jint)x;
}

JS_HIDDEN void js_vm_rewrap_resident_opcode(js_vm_program *p, int index, jint opcode, int step, int pc_after_fetch, int stack_depth) {
    if (!p || index < 0 || index >= p->insn_count) return;
    jint next_epoch = js_vm_next_opcode_epoch(p, index, p->insns[index].opcode_epoch, step, pc_after_fetch, stack_depth);
    p->insns[index].opcode_epoch = next_epoch;
    p->insns[index].opcode = opcode ^ js_vm_resident_opcode_mask(p, index);
}

JS_HIDDEN void js_vm_rotate_resident_block(js_vm_program *p, int anchor, int step, uint32_t dispatch_drift_state, int pc_after_fetch, int stack_depth) {
    if (!p || p->insn_count <= 1) return;
    uint32_t seed = (uint32_t)js_vm_load_resident_build_seed(p) ^ (uint32_t)js_vm_load_resident_mac_key(p) ^ dispatch_drift_state;
    seed ^= (uint32_t)(step * 0x9E3779B1u) ^ (uint32_t)(pc_after_fetch * 0x85EBCA77u) ^ (uint32_t)(stack_depth * 0xC2B2AE3Du);
    seed ^= seed >> 16;
    seed *= 0x7FEB352Du;
    seed ^= seed >> 15;
    int window = 2 + (int)(seed & 0x3u);
    if (window > p->insn_count) window = p->insn_count;
    int start = anchor - (int)((seed >> 8) % (uint32_t)window);
    while (start < 0) start += p->insn_count;
    start %= p->insn_count;
    int total = p->insn_count;
    jint inline_opcodes[32];
    jint *opcodes = total <= (int)(sizeof(inline_opcodes) / sizeof(inline_opcodes[0])) ? inline_opcodes : (jint*)calloc((size_t)total, sizeof(jint));
    if (!opcodes) return;
    for (int index = 0; index < total; index++) {
        opcodes[index] = js_vm_load_resident_opcode(p, index);
    }
    p->resident_rotation_epoch ^= js_vbc4_rotl32_core(seed, (anchor + window) & 31) ^ ((uint32_t)window * 0x165667B1u);
    for (int index = 0; index < total; index++) {
        p->insns[index].opcode = opcodes[index] ^ js_vm_resident_opcode_mask(p, index);
    }
    for (int offset = 0; offset < window; offset++) {
        int index = (start + offset) % total;
        jint next_epoch = js_vm_next_opcode_epoch(
            p,
            index,
            p->insns[index].opcode_epoch ^ (jint)(seed + (uint32_t)(offset * 0x45D9F3Bu)),
            step + offset,
            pc_after_fetch,
            stack_depth + offset
        );
        p->insns[index].opcode_epoch = next_epoch;
        p->insns[index].opcode = opcodes[index] ^ js_vm_resident_opcode_mask(p, index);
    }
    js_vbc4_wipe_volatile(opcodes, (size_t)total * sizeof(jint));
    if (opcodes != inline_opcodes) free(opcodes);
}

JS_HIDDEN jint js_vm_resident_operand_mask(const js_vm_program *p, int insn_index, int operand_index) {
    uint32_t seed = (uint32_t)js_vm_load_resident_build_seed(p);
    uint32_t x = (uint32_t)js_vm_load_resident_mac_key(p) ^ ((seed << 13) | (seed >> 19));
    x ^= (uint32_t)(insn_index * 0x9E3779B1u) ^ (uint32_t)(operand_index * 0x85EBCA77u);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return (jint)x;
}

JS_HIDDEN jint js_vm_store_resident_operand(const js_vm_program *p, int insn_index, int operand_index, jint operand) {
    return operand ^ js_vm_resident_operand_mask(p, insn_index, operand_index);
}

JS_HIDDEN jint js_vm_load_resident_operand(const js_vm_program *p, int insn_index, int operand_index) {
    if (!p || insn_index < 0 || insn_index >= p->insn_count) return 0;
    if (operand_index < 0 || operand_index >= p->insns[insn_index].op_count || !p->insns[insn_index].ops) return 0;
    return p->insns[insn_index].ops[operand_index] ^ js_vm_resident_operand_mask(p, insn_index, operand_index);
}

JS_HIDDEN jint js_vm_resident_exception_mask(const js_vm_program *p, int exception_index, int field_index) {
    uint32_t seed = (uint32_t)js_vm_load_resident_build_seed(p);
    uint32_t x = (uint32_t)js_vm_load_resident_mac_key(p) ^ ((seed << 17) | (seed >> 15));
    x ^= (uint32_t)(exception_index * 0x27D4EB2Fu) ^ (uint32_t)(field_index * 0x165667B1u);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return (jint)x;
}

JS_HIDDEN jint js_vm_store_resident_exception_field(const js_vm_program *p, int exception_index, int field_index, jint value) {
    return value ^ js_vm_resident_exception_mask(p, exception_index, field_index);
}

JS_HIDDEN jint js_vm_load_resident_exception_field(const js_vm_program *p, int exception_index, int field_index, jint value) {
    if (!p || exception_index < 0 || exception_index >= p->exception_count || field_index < 0 || field_index > 3) return 0;
    return value ^ js_vm_resident_exception_mask(p, exception_index, field_index);
}

JS_HIDDEN js_vm_exception js_vm_load_resident_exception(const js_vm_program *p, int exception_index) {
    js_vm_exception decoded;
    memset(&decoded, 0, sizeof(decoded));
    if (!p || exception_index < 0 || exception_index >= p->exception_count || !p->exceptions) return decoded;
    decoded.start = js_vm_load_resident_exception_field(p, exception_index, 0, p->exceptions[exception_index].start);
    decoded.end = js_vm_load_resident_exception_field(p, exception_index, 1, p->exceptions[exception_index].end);
    decoded.handler = js_vm_load_resident_exception_field(p, exception_index, 2, p->exceptions[exception_index].handler);
    decoded.type_cp = js_vm_load_resident_exception_field(p, exception_index, 3, p->exceptions[exception_index].type_cp);
    return decoded;
}

JS_HIDDEN void js_vm_free_program(JNIEnv *env, js_vm_program *p) {
    if (!p) return;
    if (p->cp) {
        for (int i = 0; i < p->cp_count; i++) {
            if (p->cp[i].s) { size_t sl = strlen(p->cp[i].s); js_vbc4_wipe_volatile(p->cp[i].s, sl); }
            free(p->cp[i].s);
            if (p->cp[i].enc) { js_vbc4_wipe_volatile(p->cp[i].enc, (size_t)p->cp[i].enc_len); free(p->cp[i].enc); }
        }
        js_vbc4_wipe_volatile(p->cp, (size_t)p->cp_count * sizeof(js_vm_cp));
        free(p->cp);
    }
    if (p->symbols) {
        for (int i = 0; i < p->symbol_count; i++) js_vm_symbol_cache_clear_entry(env, &p->symbols[i]);
        js_vbc4_wipe_volatile(p->symbols, (size_t)p->symbol_count * sizeof(js_vm_symbol_cache_entry));
        free(p->symbols);
    }
    if (p->original_owner) { js_vbc4_wipe_volatile(p->original_owner, strlen(p->original_owner)); free(p->original_owner); }
    if (p->original_name) { js_vbc4_wipe_volatile(p->original_name, strlen(p->original_name)); free(p->original_name); }
    if (p->original_desc) { js_vbc4_wipe_volatile(p->original_desc, strlen(p->original_desc)); free(p->original_desc); }
    if (p->reg_program.insns) {
        js_vbc4_wipe_volatile(p->reg_program.insns, (size_t)p->reg_program.insn_count * sizeof(js_vm_reg_insn));
        free(p->reg_program.insns);
    }
    if (p->insns) {
        if (!p->borrowed_insn_operands) {
            for (int i = 0; i < p->insn_count; i++) { if (p->insns[i].ops) { js_vbc4_wipe_volatile(p->insns[i].ops, (size_t)p->insns[i].op_count * sizeof(jint)); } free(p->insns[i].ops); }
        }
        if (!p->borrowed_insns) js_vbc4_wipe_volatile(p->insns, (size_t)p->insn_count * sizeof(js_vm_insn));
        free(p->insns);
    }
    if (p->exceptions) { js_vbc4_wipe_volatile(p->exceptions, (size_t)p->exception_count * sizeof(js_vm_exception)); free(p->exceptions); }
    js_vbc4_wipe_volatile(p, sizeof(*p));
}

/* BEGIN MOVED JS_HELPERS CORE: legacy VM/security bodies split out of js_helpers.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * JavaShroud Native Helpers (js_helpers.c)
 * JNI native implementations for all protection runtime helpers.
 * Compiled alongside js_kernel.c into the same shared library.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <stdarg.h>
#include "js_native_common.h"
#include "js_crypto.h"
#include "js_antidebug.h"
#include "js_jni_runtime.h"
#include "js_protected_section.h"
#include "js_vm_core.h"
#include "js_vm_internal.h"
#include "js_vm_symbol.h"
#include "js_vm_resource.h"
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif
#include "native_secrets.inc"

/* ---- Item #4: native critical-region pre-decrypt protection ----
 *
 * Selected pure, relocation-free hot functions are emitted into a dedicated code
 * section (".jsx" on PE/ELF targets). At build time a native-format-aware patcher
 * (Kotlin side) encrypts the section body with a SHA-256 keystream and flips a seal
 * marker. At load time, BEFORE any protected function runs, an ELF/PE constructor locates
 * the section in the in-memory image, decrypts
 * it in place, and restores executable protection.
 *
 * Safety / loader stability:
 *  - The seal marker gates decryption. If the build-time patcher did not run (e.g.
 *    a platform/format the patcher cannot safely parse, or relocations overlap the
 *    section), the marker stays in the "plaintext" state and the constructor is a
 *    no-op, so the binary is always loadable and correct.
 *  - Only leaf functions with no external references are placed in the section, so
 *    the image carries no base relocations into the protected range; the patcher
 *    independently verifies this and fails open if violated.
 */
#if JS_PROTECTED_SECTION_ENABLED
#define JS_PROTECTED __attribute__((noinline, section(JS_PROTECTED_SECTION_NAME)))
#else
#define JS_PROTECTED __attribute__((noinline))
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define JS_THREAD_LOCAL _Thread_local
#elif defined(_MSC_VER)
#define JS_THREAD_LOCAL __declspec(thread)
#else
#define JS_THREAD_LOCAL __thread
#endif

/* Thread-local secret decrypt buffer for inline use in JNI calls.
 * Each call decrypts the requested secret and returns a pointer to a
 * static buffer. The buffer is wiped on the NEXT js_secret_get call.
 * Callers must NOT store the returned pointer beyond the immediate use. */
static JS_THREAD_LOCAL char js_secret_buf[128];
static JS_THREAD_LOCAL int js_secret_buf_dirty = 0;
static const char* js_secret_get(int id);
static void js_secret_aes_ctr_decode(const unsigned char *enc, int len, int idx, char *out);

/* Secret IDs for js_secret_get */
#define JS_SECRET_ID_SECURITY_EXCEPTION_CLASS 0
#define JS_SECRET_ID_MANAGEMENT_FACTORY_CLASS 1
#define JS_SECRET_ID_THREAD_CLASS 2
#define JS_SECRET_ID_SYSTEM_CLASS 3
#define JS_SECRET_ID_RUNTIME_CLASS 4
#define JS_SECRET_ID_STACK_TRACE_ELEMENT_CLASS 5
#define JS_SECRET_ID_ARRAY_LIST_CLASS 6
#define JS_SECRET_ID_IOEXCEPTION_CLASS 7
#define JS_SECRET_ID_GET_INPUT_ARGS 8
#define JS_SECRET_ID_GET_STACK_TRACE 9
#define JS_SECRET_ID_GET_CLASS_NAME 10
#define JS_SECRET_ID_HASH_CODE 11
#define JS_SECRET_ID_GET_CLASS_LOADER 12
#define JS_SECRET_ID_LOAD_CLASS 13
#define JS_SECRET_ID_FOR_NAME 14
#define JS_SECRET_ID_GET_RESOURCEAsStream 15

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

/* ---- Strong-signal anti-debug syscall/kernel-boundary headers ---- *
 * High-confidence checks deliberately avoid easily-hooked userland helpers
 * (IsDebuggerPresent, libc fopen on /proc) and instead read kernel-owned state
 * through raw syscalls (Linux) or direct NT/PEB structures (Windows). */
#if defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#endif
#if defined(__APPLE__)
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

#define JS_LOCAL JS_HIDDEN

JS_LOCAL jobject JNICALL jsn_r20(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args);

#if defined(_MSC_VER)
#define JS_USED __declspec(selectany)
#elif defined(__GNUC__) || defined(__clang__)
#define JS_USED __attribute__((used))
#else
#define JS_USED
#endif
static const char js_sealed_jni_abi_marker[] JS_USED = "JNI_OnLoad\0RegisterNatives\0j.l\0j.b\0j.m\0Resource\0entryToken\0Runtime\0Resources\0(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;\0(J[Ljava/lang/Object;)Ljava/lang/Object;\0(J)V\0(JI)V";

static void js_vm_write_be32_early(unsigned char out[4], uint32_t value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static uint32_t js_vm_entry_integrity_state_early(void) {
    return 0x10429F6Cu;
}

static uint32_t js_vm_clean_entry_integrity_state(void) {
    return 0x10429F6Cu;
}

static void js_vm_write_entry_integrity_bytes_early(unsigned char out[4]) {
    js_vm_write_be32_early(out, js_vm_entry_integrity_state_early());
}

static void js_vm_write_clean_entry_integrity_bytes(unsigned char out[4]) {
    js_vm_write_be32_early(out, js_vm_clean_entry_integrity_state());
}

static char* sys_prop(JNIEnv *env, const char *key) {
    jclass sc = (*env)->FindClass(env, js_secret_get(JS_SECRET_ID_SYSTEM_CLASS));
    if (js_pending_exception(env) || !sc) { js_clear_pending_exception(env); return NULL; }
    jmethodID gp = (*env)->GetStaticMethodID(env, sc, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    if (js_pending_exception(env) || !gp) { js_clear_pending_exception(env); return NULL; }
    jstring jk = (*env)->NewStringUTF(env, key);
    if (js_pending_exception(env) || !jk) { js_clear_pending_exception(env); return NULL; }
    jstring jv = (jstring)(*env)->CallStaticObjectMethod(env, sc, gp, jk);
    if (js_pending_exception(env) || !jv) { js_clear_pending_exception(env); return NULL; }
    const char *v = (*env)->GetStringUTFChars(env, jv, NULL);
    if (js_pending_exception(env) || !v) { js_clear_pending_exception(env); return NULL; }
    char *cp = js_strdup(v);
    (*env)->ReleaseStringUTFChars(env, jv, v);
    return cp;
}

static char* js_first_loader_owner_from_property(JNIEnv *env) {
    char *owners = sys_prop(env, "j.l");
    if (!owners || !owners[0]) return owners;
    char *line = owners;
    while (*line) {
        while (*line == '\n' || *line == '\r' || *line == ' ' || *line == '\t') line++;
        if (!*line) break;
        char *end = line;
        while (*end && *end != '\n' && *end != '\r') end++;
        char saved = *end;
        *end = 0;
        if (*line) {
            char *selected = js_strdup(line);
            free(owners);
            return selected;
        }
        *end = saved;
        line = saved ? end + 1 : end;
    }
    free(owners);
    return NULL;
}

typedef struct js_vm_guest_frame {
    const char *owner;
    const char *name;
    const char *desc;
} js_vm_guest_frame;
static JS_THREAD_LOCAL js_vm_guest_frame js_vm_guest_frames[64];
static JS_THREAD_LOCAL int js_vm_guest_frame_count = 0;

/* Bound the depth of native-to-native VM dispatch (one virtualized method
 * directly invoking another preloaded virtualized method inside the C
 * interpreter). Deeply recursive guest algorithms (e.g. minimax search) would
 * otherwise grow the native C stack unbounded and fault with an access
 * violation, or collapse performance by recursing entirely in the interpreter.
 * When the limit is reached the nested fast-path declines (returns 0) and the
 * caller falls back to a normal JNI invocation of the target's Java dispatch
 * stub, so the JVM manages the call stack. This is semantically equivalent:
 * the same virtualized method runs, only via a JVM call instead of a native
 * recursion. */
#define JS_VM_NESTED_DISPATCH_MAX_DEPTH 1
static JS_THREAD_LOCAL int js_vm_nested_dispatch_depth = 0;

/* ---- Item #6: cross-method shared VM dispatcher-state pool ----
 *
 * A process-wide pool of dispatcher-state words plus a running epoch. Every virtualized
 * method seeds its per-run dispatch-drift state from this shared pool (mixed with its
 * own identity) and evolves the pool on exit. The effect is interprocedural scheduling
 * of VM slices: a method's observed dispatch structure depends on which virtualized
 * methods executed before it, so an attacker cannot reconstruct a single method's
 * dispatch graph in isolation -- the slices share live cross-method state.
 *
 * This is strictly dispatch-layer state: js_vm_case_match is salt-invariant, so the
 * shared state only reshapes the (already obfuscated) dispatch salt/drift and never
 * changes which handler a decoded opcode selects. Program semantics are unaffected.
 */
#define JS_VM_SHARED_STATE_POOL_SIZE 16
static volatile uint32_t js_vm_shared_dispatch_pool[JS_VM_SHARED_STATE_POOL_SIZE];
static volatile uint32_t js_vm_shared_dispatch_epoch = 0;
static volatile int js_vm_shared_dispatch_seeded = 0;


JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);
static void js_hmac_sha256_with_key(const unsigned char *key, int key_len, const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]);
static void js_write_be32_tmp(unsigned char out[4], uint32_t value);
static uint32_t js_vm_entry_integrity_state(void);
static void js_vm_write_entry_integrity_bytes(unsigned char out[4]);
static void js_vm_write_clean_entry_integrity_bytes(unsigned char out[4]);
static void js_vbc4_copy_scoped_master_key(unsigned char out[32]);
static void js_vbc4_session_integrity_material(unsigned char out[32]);
static void js_vbc4_hmac_with_scoped_master_key(const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]);

#define JS_VM_NOP 0x00
#define JS_VM_ACONST_NULL 0x01
#define JS_VM_ICONST 0x02
#define JS_VM_LCONST 0x03
#define JS_VM_FCONST 0x04
#define JS_VM_DCONST 0x05
#define JS_VM_BIPUSH 0x06
#define JS_VM_SIPUSH 0x07
#define JS_VM_LDC_INT 0x08
#define JS_VM_LDC_LONG 0x09
#define JS_VM_LDC_FLOAT 0x0A
#define JS_VM_LDC_DOUBLE 0x0B
#define JS_VM_LDC_STRING 0x0C
#define JS_VM_LDC_TYPE 0x0D
#define JS_VM_LDC_HANDLE 0x0E
#define JS_VM_ILOAD 0x10
#define JS_VM_LLOAD 0x11
#define JS_VM_FLOAD 0x12
#define JS_VM_DLOAD 0x13
#define JS_VM_ALOAD 0x14
#define JS_VM_ISTORE 0x20
#define JS_VM_LSTORE 0x21
#define JS_VM_FSTORE 0x22
#define JS_VM_DSTORE 0x23
#define JS_VM_ASTORE 0x24
#define JS_VM_IINC 0x25
#define JS_VM_RET 0x26
#define JS_VM_POP 0x30
#define JS_VM_POP2 0x31
#define JS_VM_DUP 0x32
#define JS_VM_DUP_X1 0x33
#define JS_VM_DUP_X2 0x34
#define JS_VM_DUP2 0x35
#define JS_VM_SWAP 0x36
#define JS_VM_DUP2_X1 0xF6
#define JS_VM_DUP2_X2 0xF7
#define JS_VM_IADD 0x40
#define JS_VM_LADD 0x41
#define JS_VM_FADD 0x42
#define JS_VM_DADD 0x43
#define JS_VM_ISUB 0x44
#define JS_VM_LSUB 0x45
#define JS_VM_FSUB 0x46
#define JS_VM_DSUB 0x47
#define JS_VM_IMUL 0x48
#define JS_VM_LMUL 0x49
#define JS_VM_FMUL 0x4A
#define JS_VM_DMUL 0x4B
#define JS_VM_IDIV 0x4C
#define JS_VM_LDIV 0x4D
#define JS_VM_FDIV 0x4E
#define JS_VM_DDIV 0x4F
#define JS_VM_IREM 0x50
#define JS_VM_LREM 0x51
#define JS_VM_FREM 0xF2
#define JS_VM_DREM 0xF3
#define JS_VM_INEG 0x52
#define JS_VM_LNEG 0x53
#define JS_VM_FNEG 0x54
#define JS_VM_DNEG 0x55
#define JS_VM_ISHL 0x56
#define JS_VM_ISHR 0x57
#define JS_VM_IUSHR 0x58
#define JS_VM_LSHL 0x59
#define JS_VM_LSHR 0x5A
#define JS_VM_LUSHR 0x5B
#define JS_VM_IAND 0x5C
#define JS_VM_LAND 0x5D
#define JS_VM_IOR 0x5E
#define JS_VM_LOR 0x5F
#define JS_VM_LCMP 0x60
#define JS_VM_FCMPL 0x61
#define JS_VM_FCMPG 0x62
#define JS_VM_DCMPL 0x63
#define JS_VM_DCMPG 0x64
#define JS_VM_IXOR 0x68
#define JS_VM_LXOR 0x69
#define JS_VM_I2L 0x6A
#define JS_VM_I2F 0x6B
#define JS_VM_I2D 0x6C
#define JS_VM_L2I 0x6D
#define JS_VM_L2F 0x6E
#define JS_VM_L2D 0x6F
#define JS_VM_IFEQ 0x70
#define JS_VM_IFNE 0x71
#define JS_VM_IFLT 0x72
#define JS_VM_IFGE 0x73
#define JS_VM_IFGT 0x74
#define JS_VM_IFLE 0x75
#define JS_VM_IF_ICMPEQ 0x76
#define JS_VM_IF_ICMPNE 0x77
#define JS_VM_IF_ICMPLT 0x78
#define JS_VM_IF_ICMPGE 0x79
#define JS_VM_IF_ICMPGT 0x7A
#define JS_VM_IF_ICMPLE 0x7B
#define JS_VM_IF_ACMPEQ 0x7C
#define JS_VM_IF_ACMPNE 0x7D
#define JS_VM_GOTO 0x7E
#define JS_VM_JSR 0x7F
#define JS_VM_IFNULL 0x80
#define JS_VM_IFNONNULL 0x81
#define JS_VM_F2I 0x88
#define JS_VM_F2L 0x89
#define JS_VM_F2D 0x8A
#define JS_VM_D2I 0x8B
#define JS_VM_D2L 0x8C
#define JS_VM_D2F 0x8D
#define JS_VM_I2B 0x8E
#define JS_VM_I2C 0x8F
#define JS_VM_IRETURN 0x90
#define JS_VM_LRETURN 0x91
#define JS_VM_FRETURN 0x92
#define JS_VM_DRETURN 0x93
#define JS_VM_ARETURN 0x94
#define JS_VM_RETURN 0x95
#define JS_VM_ATHROW 0x96
#define JS_VM_I2S 0x9A
#define JS_VM_GETSTATIC 0xA0
#define JS_VM_PUTSTATIC 0xA1
#define JS_VM_GETFIELD 0xA2
#define JS_VM_PUTFIELD 0xA3
#define JS_VM_INVOKEVIRTUAL 0xB0
#define JS_VM_INVOKESPECIAL 0xB1
#define JS_VM_INVOKESTATIC 0xB2
#define JS_VM_INVOKEINTERFACE 0xB3
#define JS_VM_INVOKEDYNAMIC 0xB4
#define JS_VM_NEW 0xC0
#define JS_VM_NEWARRAY 0xC1
#define JS_VM_ANEWARRAY 0xC2
#define JS_VM_ARRAYLENGTH 0xC3
#define JS_VM_CHECKCAST 0xC4
#define JS_VM_INSTANCEOF 0xC5
#define JS_VM_MULTIANEWARRAY 0xC6
#define JS_VM_IALOAD 0xD0
#define JS_VM_LALOAD 0xD1
#define JS_VM_FALOAD 0xD2
#define JS_VM_DALOAD 0xD3
#define JS_VM_AALOAD 0xD4
#define JS_VM_BALOAD 0xD5
#define JS_VM_CALOAD 0xD6
#define JS_VM_SALOAD 0xD7
#define JS_VM_IASTORE 0xD8
#define JS_VM_LASTORE 0xD9
#define JS_VM_FASTORE 0xDA
#define JS_VM_DASTORE 0xDB
#define JS_VM_AASTORE 0xDC
#define JS_VM_BASTORE 0xDD
#define JS_VM_CASTORE 0xDE
#define JS_VM_SASTORE 0xDF
#define JS_VM_MONITORENTER 0xE0
#define JS_VM_MONITOREXIT 0xE1
#define JS_VM_ICONST_ALT 0xE8
#define JS_VM_IADD_ALT 0xE9
#define JS_VM_ISUB_ALT 0xEA
#define JS_VM_ILOAD_ALT 0xEB
#define JS_VM_ISTORE_ALT 0xEC
#define JS_VM_IRETURN_ALT 0xED
#define JS_VM_ICONST_ALT2 0xE2
#define JS_VM_IADD_ALT2 0xE3
#define JS_VM_ISUB_ALT2 0xE4
#define JS_VM_ILOAD_ALT2 0xE5
#define JS_VM_ISTORE_ALT2 0xE6
#define JS_VM_IRETURN_ALT2 0xE7
#define JS_VM_IMUL_ALT 0x37
#define JS_VM_IXOR_ALT 0x38
#define JS_VM_IAND_ALT 0x39
#define JS_VM_IOR_ALT 0x3A
#define JS_VM_ISHL_ALT 0x3B
#define JS_VM_ISHR_ALT 0x3C
#define JS_VM_IUSHR_ALT 0x3D
#define JS_VM_INEG_ALT 0x3E
#define JS_VM_LADD_ALT 0x3F
#define JS_VM_ALOAD_ALT 0x15
#define JS_VM_LLOAD_ALT 0x16
#define JS_VM_FLOAD_ALT 0x17
#define JS_VM_DLOAD_ALT 0x18
#define JS_VM_ASTORE_ALT 0x27
#define JS_VM_LSTORE_ALT 0x28
#define JS_VM_FSTORE_ALT 0x29
#define JS_VM_DSTORE_ALT 0x2A
#define JS_VM_IALOAD_ALT 0xA4
#define JS_VM_IASTORE_ALT 0xA5
#define JS_VM_AALOAD_ALT 0xA6
#define JS_VM_AASTORE_ALT 0xA7
#define JS_VM_GETFIELD_ALT 0xA8
#define JS_VM_PUTFIELD_ALT 0xA9
#define JS_VM_GETSTATIC_ALT 0xAA
#define JS_VM_PUTSTATIC_ALT 0xAB
#define JS_VM_GOTO_ALT 0x82
#define JS_VM_IFEQ_ALT 0x83
#define JS_VM_IFNE_ALT 0x84
#define JS_VM_IF_ICMPEQ_ALT 0x85
#define JS_VM_IF_ICMPNE_ALT 0x86
#define JS_VM_IFNULL_ALT 0x87
#define JS_VM_IFNONNULL_ALT 0x97
#define JS_VM_DUP_ALT 0x98
#define JS_VM_POP_ALT 0x99
#define JS_VM_SWAP_ALT 0x9B
#define JS_VM_BIPUSH_ALT 0x0F
#define JS_VM_SIPUSH_ALT 0x19
#define JS_VM_LCONST_ALT 0x1A
#define JS_VM_FCONST_ALT 0x1B
#define JS_VM_DCONST_ALT 0x1C
#define JS_VM_IREM_ALT 0x1D
#define JS_VM_LREM_ALT 0x1E
#define JS_VM_LAND_ALT 0x1F
#define JS_VM_LOR_ALT 0x2B
#define JS_VM_LXOR_ALT 0x2C
#define JS_VM_IFLT_ALT 0x2D
#define JS_VM_IFGE_ALT 0x2E
#define JS_VM_IFGT_ALT 0x2F
#define JS_VM_IFLE_ALT 0xF4
#define JS_VM_IF_ICMPLT_ALT 0xF5
#define JS_VM_IF_ICMPGE_ALT 0x65
#define JS_VM_IF_ICMPGT_ALT 0x66
#define JS_VM_IF_ICMPLE_ALT 0x67
#define JS_VM_IF_ACMPEQ_ALT 0x9C
#define JS_VM_IF_ACMPNE_ALT 0x9D
#define JS_VM_LRETURN_ALT 0x9E
#define JS_VM_FRETURN_ALT 0x9F
#define JS_VM_DRETURN_ALT 0xAC
#define JS_VM_ARETURN_ALT 0xAD
#define JS_VM_RETURN_ALT 0xAE
#define JS_VM_ATHROW_ALT 0xAF
#define JS_VM_I2L_ALT 0xB5
#define JS_VM_I2F_ALT 0xB6
#define JS_VM_I2D_ALT 0xB7
#define JS_VM_L2I_ALT 0xB8
#define JS_VM_L2F_ALT 0xB9
#define JS_VM_L2D_ALT 0xBA
#define JS_VM_F2I_ALT 0xBB
#define JS_VM_F2L_ALT 0xBC
#define JS_VM_F2D_ALT 0xBD
#define JS_VM_D2I_ALT 0xBE
#define JS_VM_D2L_ALT 0xBF
#define JS_VM_D2F_ALT 0xC7
#define JS_VM_I2B_ALT 0xC8
#define JS_VM_I2C_ALT 0xC9
#define JS_VM_I2S_ALT 0xCA
#define JS_VM_NEW_ALT 0xCB
#define JS_VM_NEWARRAY_ALT 0xCC
#define JS_VM_ANEWARRAY_ALT 0xCD
#define JS_VM_ARRAYLENGTH_ALT 0xCE
#define JS_VM_CHECKCAST_ALT 0xCF
#define JS_VM_INSTANCEOF_ALT 0xEE
#define JS_VM_MULTIANEWARRAY_ALT 0xEF
#define JS_VM_TABLESWITCH 0xF0
#define JS_VM_LOOKUPSWITCH 0xF1
#define JS_VM_MAXS 0xFE
#define JS_VM_UNSUPPORTED 0xFF

#define JS_VM_REG_OPERAND_CONT 0xFC
#define JS_VM_REG_META 0xFD
#define JS_VM_REG_FLAG_EXECUTABLE 0x0001
#define JS_VM_REG_FLAG_SUPER 0x0002
#define JS_VM_REG_FLAG_FOLDED 0x0004
#define JS_VM_REG_FLAG_CONTINUATION 0x8000
#define JS_VM_SUPER_CONST 0xF8
#define JS_VM_SUPER_INT_ARITH 0xF9
#define JS_VM_SUPER_CMP_BRANCH 0xFA
#define JS_VM_SUPER_INVOKE 0xFB
#define JS_VM_SUPER_BASE 0xF8
#define JS_VBC4_FLAG_ZSTD_SECTIONS 0x0400u
#define JS_VBC4_FLAG_BLOCK_DISPATCH 0x0800u
#define JS_VBC4_REQUIRED_FLAGS 0x0FFFu
#define JS_VBC4_FLAG_NESTED_VM 0x1000u
#define JS_VBC4_NESTED_MAGIC 0x4E56u
#define JS_VBC4_NESTED_VERSION 1u
#define JS_VBC4_NESTED_FIELD_COUNT 6u
#define JS_VBC4_NESTED_MICROS_PER_ROW 7u
#define JS_VBC4_NESTED_FIELD_OPCODE_BASE 0x7000u
#define JS_VBC4_NESTED_COMMIT_OPCODE_BASE 0x6000u
#define JS_VBC4_NESTED_COMMIT_SLOT 0x7Fu
#define JS_VBC4_SIMULATION_PROBE_GATE 0x3F
#define JS_VBC4_CP_SECTION_VERSION 1u
#define JS_VBC4_SECTION_CONSTANT_POOL_ENTRY 9u
JS_HIDDEN int js_vm_execute(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret);
JS_HIDDEN js_vm_object_result js_vm_execute_prepared_program(JNIEnv *env, js_vm_program *program, jobjectArray args);
JS_HIDDEN void js_vm_clear_execution_program(js_vm_program *program);
static volatile int js_vm_last_failure_pc = -1;
static volatile int js_vm_last_failure_opcode = -1;
static volatile int js_vm_last_failure_sp = -1;
static volatile int js_vm_last_failure_raw_opcode = -1;
static volatile int js_vm_last_failure_mask = -1;
static volatile int js_vm_last_failure_epoch = -1;
static volatile int js_vm_last_failure_cached = -1;
static volatile int js_vm_last_failure_insn_count = -1;
static volatile int js_vm_last_failure_step = -1;
static volatile int js_vm_last_failure_step_limit = -1;
static char js_vm_last_failure_detail[256];
JS_HIDDEN volatile int js_vm_last_validation_error = 0;
#define JS_RRK_SHARE_COUNT 3
static unsigned char js_runtime_resource_key_shares[JS_RRK_SHARE_COUNT][32];
/* Reassemble the per-build root key from XOR shares. JS_PROTECTED leaf taking
 * the shares by pointer, so the protected .jsx section carries no global
 * reference and stays relocation-free (required by the section packer). The
 * root key only exists transiently in the caller buffer and is wiped after use. */
JS_PROTECTED static void js_rrk_xor_assemble(const unsigned char *shares, int share_count, unsigned char out[32]) {
    for (int b = 0; b < 32; b++) {
        unsigned char acc = 0;
        for (int s = 0; s < share_count; s++) acc = (unsigned char)(acc ^ shares[s * 32 + b]);
        out[b] = acc;
    }
}
static volatile int js_runtime_resource_key_ready = 0;
JS_HIDDEN int js_vm_parse_program(const unsigned char *data, int len, js_vm_program *p, const unsigned char *state_binding, int state_binding_len);
JS_HIDDEN unsigned char* js_runtime_resource_decode_owned(const unsigned char *raw, int raw_len, int *out_len);
JS_HIDDEN char* js_lookup_bound_method(JNIEnv *env, const char *original_class, const char *method_name, const char *signature);
static int js_vm_invoke_method(JNIEnv *env, js_vm_program *p, int cp_idx, int opcode, js_vm_value *stack, int stack_cap, int *sp, js_vm_value *locals, int local_cap, uint32_t local_perm_mul, uint32_t local_perm_add);
static int js_vm_rebind_self_call_locals(JNIEnv *env, js_vm_symbol_cache_entry *symbol, jobject target, const jvalue *args, js_vm_value *locals, int local_cap, uint32_t local_perm_mul, uint32_t local_perm_add);
JS_HIDDEN jobject js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args);
JS_HIDDEN int js_vm_build_execution_program_from_registers(js_vm_program *source, js_vm_program *execution);
JS_HIDDEN int js_vm_decode_cp_entry(js_vm_program *p, int cp_idx, js_vm_cp *out);

JS_PROTECTED static jint js_vm_canonical_opcode(jint opcode) {
    switch (opcode) {
        case JS_VM_ICONST_ALT: return JS_VM_ICONST;
        case JS_VM_IADD_ALT: return JS_VM_IADD;
        case JS_VM_ISUB_ALT: return JS_VM_ISUB;
        case JS_VM_ILOAD_ALT: return JS_VM_ILOAD;
        case JS_VM_ISTORE_ALT: return JS_VM_ISTORE;
        case JS_VM_IRETURN_ALT: return JS_VM_IRETURN;
        case JS_VM_ICONST_ALT2: return JS_VM_ICONST;
        case JS_VM_IADD_ALT2: return JS_VM_IADD;
        case JS_VM_ISUB_ALT2: return JS_VM_ISUB;
        case JS_VM_ILOAD_ALT2: return JS_VM_ILOAD;
        case JS_VM_ISTORE_ALT2: return JS_VM_ISTORE;
        case JS_VM_IRETURN_ALT2: return JS_VM_IRETURN;
        case JS_VM_IMUL_ALT: return JS_VM_IMUL;
        case JS_VM_IXOR_ALT: return JS_VM_IXOR;
        case JS_VM_IAND_ALT: return JS_VM_IAND;
        case JS_VM_IOR_ALT: return JS_VM_IOR;
        case JS_VM_ISHL_ALT: return JS_VM_ISHL;
        case JS_VM_ISHR_ALT: return JS_VM_ISHR;
        case JS_VM_IUSHR_ALT: return JS_VM_IUSHR;
        case JS_VM_INEG_ALT: return JS_VM_INEG;
        case JS_VM_LADD_ALT: return JS_VM_LADD;
        case JS_VM_ALOAD_ALT: return JS_VM_ALOAD;
        case JS_VM_LLOAD_ALT: return JS_VM_LLOAD;
        case JS_VM_FLOAD_ALT: return JS_VM_FLOAD;
        case JS_VM_DLOAD_ALT: return JS_VM_DLOAD;
        case JS_VM_ASTORE_ALT: return JS_VM_ASTORE;
        case JS_VM_LSTORE_ALT: return JS_VM_LSTORE;
        case JS_VM_FSTORE_ALT: return JS_VM_FSTORE;
        case JS_VM_DSTORE_ALT: return JS_VM_DSTORE;
        case JS_VM_IALOAD_ALT: return JS_VM_IALOAD;
        case JS_VM_IASTORE_ALT: return JS_VM_IASTORE;
        case JS_VM_AALOAD_ALT: return JS_VM_AALOAD;
        case JS_VM_AASTORE_ALT: return JS_VM_AASTORE;
        case JS_VM_GETFIELD_ALT: return JS_VM_GETFIELD;
        case JS_VM_PUTFIELD_ALT: return JS_VM_PUTFIELD;
        case JS_VM_GETSTATIC_ALT: return JS_VM_GETSTATIC;
        case JS_VM_PUTSTATIC_ALT: return JS_VM_PUTSTATIC;
        case JS_VM_GOTO_ALT: return JS_VM_GOTO;
        case JS_VM_IFEQ_ALT: return JS_VM_IFEQ;
        case JS_VM_IFNE_ALT: return JS_VM_IFNE;
        case JS_VM_IF_ICMPEQ_ALT: return JS_VM_IF_ICMPEQ;
        case JS_VM_IF_ICMPNE_ALT: return JS_VM_IF_ICMPNE;
        case JS_VM_IFNULL_ALT: return JS_VM_IFNULL;
        case JS_VM_IFNONNULL_ALT: return JS_VM_IFNONNULL;
        case JS_VM_DUP_ALT: return JS_VM_DUP;
        case JS_VM_POP_ALT: return JS_VM_POP;
        case JS_VM_SWAP_ALT: return JS_VM_SWAP;
        case JS_VM_BIPUSH_ALT: return JS_VM_BIPUSH;
        case JS_VM_SIPUSH_ALT: return JS_VM_SIPUSH;
        case JS_VM_LCONST_ALT: return JS_VM_LCONST;
        case JS_VM_FCONST_ALT: return JS_VM_FCONST;
        case JS_VM_DCONST_ALT: return JS_VM_DCONST;
        case JS_VM_IREM_ALT: return JS_VM_IREM;
        case JS_VM_LREM_ALT: return JS_VM_LREM;
        case JS_VM_LAND_ALT: return JS_VM_LAND;
        case JS_VM_LOR_ALT: return JS_VM_LOR;
        case JS_VM_LXOR_ALT: return JS_VM_LXOR;
        case JS_VM_IFLT_ALT: return JS_VM_IFLT;
        case JS_VM_IFGE_ALT: return JS_VM_IFGE;
        case JS_VM_IFGT_ALT: return JS_VM_IFGT;
        case JS_VM_IFLE_ALT: return JS_VM_IFLE;
        case JS_VM_IF_ICMPLT_ALT: return JS_VM_IF_ICMPLT;
        case JS_VM_IF_ICMPGE_ALT: return JS_VM_IF_ICMPGE;
        case JS_VM_IF_ICMPGT_ALT: return JS_VM_IF_ICMPGT;
        case JS_VM_IF_ICMPLE_ALT: return JS_VM_IF_ICMPLE;
        case JS_VM_IF_ACMPEQ_ALT: return JS_VM_IF_ACMPEQ;
        case JS_VM_IF_ACMPNE_ALT: return JS_VM_IF_ACMPNE;
        case JS_VM_LRETURN_ALT: return JS_VM_LRETURN;
        case JS_VM_FRETURN_ALT: return JS_VM_FRETURN;
        case JS_VM_DRETURN_ALT: return JS_VM_DRETURN;
        case JS_VM_ARETURN_ALT: return JS_VM_ARETURN;
        case JS_VM_RETURN_ALT: return JS_VM_RETURN;
        case JS_VM_ATHROW_ALT: return JS_VM_ATHROW;
        case JS_VM_I2L_ALT: return JS_VM_I2L;
        case JS_VM_I2F_ALT: return JS_VM_I2F;
        case JS_VM_I2D_ALT: return JS_VM_I2D;
        case JS_VM_L2I_ALT: return JS_VM_L2I;
        case JS_VM_L2F_ALT: return JS_VM_L2F;
        case JS_VM_L2D_ALT: return JS_VM_L2D;
        case JS_VM_F2I_ALT: return JS_VM_F2I;
        case JS_VM_F2L_ALT: return JS_VM_F2L;
        case JS_VM_F2D_ALT: return JS_VM_F2D;
        case JS_VM_D2I_ALT: return JS_VM_D2I;
        case JS_VM_D2L_ALT: return JS_VM_D2L;
        case JS_VM_D2F_ALT: return JS_VM_D2F;
        case JS_VM_I2B_ALT: return JS_VM_I2B;
        case JS_VM_I2C_ALT: return JS_VM_I2C;
        case JS_VM_I2S_ALT: return JS_VM_I2S;
        case JS_VM_NEW_ALT: return JS_VM_NEW;
        case JS_VM_NEWARRAY_ALT: return JS_VM_NEWARRAY;
        case JS_VM_ANEWARRAY_ALT: return JS_VM_ANEWARRAY;
        case JS_VM_ARRAYLENGTH_ALT: return JS_VM_ARRAYLENGTH;
        case JS_VM_CHECKCAST_ALT: return JS_VM_CHECKCAST;
        case JS_VM_INSTANCEOF_ALT: return JS_VM_INSTANCEOF;
        case JS_VM_MULTIANEWARRAY_ALT: return JS_VM_MULTIANEWARRAY;
        default: return opcode;
    }
}

static uint32_t js_vbc4_rotl32(uint32_t value, int bits);
static uint64_t js_vm_probe_monotonic_ticks(void);
static volatile uint32_t js_vm_shared_dispatch_runtime_counter = 0;

static uint32_t js_vm_runtime_thread_state(void) {
    uintptr_t local_addr = (uintptr_t)&local_addr;
    uint64_t ticks = js_vm_probe_monotonic_ticks();
    uint32_t x = (uint32_t)local_addr ^ (uint32_t)(local_addr >> 32) ^ (uint32_t)ticks ^ (uint32_t)(ticks >> 32);
    x ^= ++js_vm_shared_dispatch_runtime_counter * (JS_VBC4_DISPATCH_MIX_A | 1u);
    x ^= x >> 16; x *= 0x7FEB352Du; x ^= x >> 15;
    return x;
}

static uint32_t js_vm_program_path_digest(const js_vm_program *p) {
    uint32_t x = JS_VBC4_DISPATCH_MIX_C ^ (uint32_t)(p ? p->entry_token : 0);
    if (!p) return x;
    x ^= (uint32_t)((uint64_t)p->entry_token >> 32);
    x ^= p->original_owner_hash ? (uint32_t)p->original_owner_hash ^ (uint32_t)(p->original_owner_hash >> 32) : 0u;
    x ^= p->original_name_hash ? js_vbc4_rotl32((uint32_t)p->original_name_hash ^ (uint32_t)(p->original_name_hash >> 32), 7) : 0u;
    x ^= p->original_desc_hash ? js_vbc4_rotl32((uint32_t)p->original_desc_hash ^ (uint32_t)(p->original_desc_hash >> 32), 13) : 0u;
    x ^= (uint32_t)p->method_local_profile ^ ((uint32_t)p->metadata_cp_index * 0x45D9F3Bu);
    x ^= x >> 15; x *= 0x2C1B3C6Du; x ^= x >> 12;
    return x;
}

/* Lazily seed the pool from a program's nonce/build-seed material so its initial value
 * is per-build specific (cross-run nondeterminism) rather than a fixed constant. */
static void js_vm_shared_dispatch_seed_once(const js_vm_program *p) {
    if (js_vm_shared_dispatch_seeded || !p) return;
    uint32_t s = (uint32_t)js_vm_load_resident_build_seed(p) ^ js_vm_runtime_thread_state() ^ js_vm_program_path_digest(p) ^ 0x243F6A88u;
    for (int i = 0; i < JS_VM_SHARED_STATE_POOL_SIZE; i++) {
        s ^= (uint32_t)p->nonce[i & 15] << ((i & 3) * 8);
        s ^= s >> 15; s *= 0x2C1B3C6Du; s ^= s >> 12; s *= 0x297A2D39u; s ^= s >> 16;
        js_vm_shared_dispatch_pool[i] = s;
    }
    js_vm_shared_dispatch_epoch = s ^ 0x9E3779B9u;
    js_vm_shared_dispatch_seeded = 1;
}

/* Derive a method's initial dispatch-drift seed from the shared pool mixed with the
 * method's own identity (entry token + insn count). Reads shared cross-method state. */
static uint32_t js_vm_shared_dispatch_seed_for(const js_vm_program *p) {
    js_vm_shared_dispatch_seed_once(p);
    uint32_t epoch = js_vm_shared_dispatch_epoch;
    uint32_t slot = js_vm_shared_dispatch_pool[epoch & (JS_VM_SHARED_STATE_POOL_SIZE - 1)];
    uint32_t mixed = slot ^ epoch ^ js_vm_runtime_thread_state() ^ js_vm_program_path_digest(p) ^ (uint32_t)(p ? p->entry_token : 0) ^ (uint32_t)(p ? p->insn_count : 0) * (JS_VBC4_DISPATCH_MIX_B | 1u);
    mixed ^= mixed >> 15; mixed *= 0x2C1B3C6Du; mixed ^= mixed >> 13;
    return mixed;
}

/* Evolve the shared pool after a method finishes so the next method observes updated
 * cross-method state. final_drift carries the method's terminal dispatch-drift value. */
static void js_vm_shared_dispatch_evolve(const js_vm_program *p, uint32_t final_drift, int dispatch_steps) {
    uint32_t epoch = js_vm_shared_dispatch_epoch + 1u;
    uint32_t idx = epoch & (JS_VM_SHARED_STATE_POOL_SIZE - 1);
    uint32_t cur = js_vm_shared_dispatch_pool[idx];
    cur ^= final_drift ^ ((uint32_t)dispatch_steps * (JS_VBC4_DISPATCH_MIX_A | 1u)) ^ (uint32_t)(p ? p->entry_token : 0);
    cur ^= cur >> 16; cur *= 0x7FEB352Du; cur ^= cur >> 15;
    js_vm_shared_dispatch_pool[idx] = cur;
    js_vm_shared_dispatch_epoch = epoch ^ (cur << 1);
}

static uint32_t js_vm_path_mix32(const char *path) {
    uint32_t x = JS_VBC4_DISPATCH_MIX_C ^ 0xA5A5u;
    if (!path) return x;
    for (const unsigned char *p = (const unsigned char*)path; *p; p++) {
        x ^= (uint32_t)(*p);
        x *= 0x45D9F3Bu;
        x ^= x >> 13;
    }
    return x;
}

static void js_vm_shared_dispatch_mix_preload(jlong entry_token, const char *resource_path, const char *manifest_path, uint32_t shard_count) {
    uint32_t epoch = js_vm_shared_dispatch_epoch + 1u;
    uint32_t idx = (epoch ^ (uint32_t)entry_token ^ shard_count) & (JS_VM_SHARED_STATE_POOL_SIZE - 1);
    uint32_t cur = js_vm_shared_dispatch_pool[idx];
    cur ^= (uint32_t)entry_token ^ (uint32_t)((uint64_t)entry_token >> 32);
    cur ^= js_vm_path_mix32(resource_path);
    cur ^= js_vbc4_rotl32(js_vm_path_mix32(manifest_path), 11);
    cur ^= shard_count * (JS_VBC4_DISPATCH_MIX_A | 1u);
    cur ^= cur >> 16;
    cur *= 0x7FEB352Du;
    cur ^= cur >> 15;
    js_vm_shared_dispatch_pool[idx] = cur;
    js_vm_shared_dispatch_epoch = epoch ^ js_vbc4_rotl32(cur, (int)(shard_count & 15u));
    js_vm_shared_dispatch_seeded = 1;
}

JS_PROTECTED static uint32_t js_vm_reg_fold_step(uint32_t state, const js_vm_reg_insn *insn) {
    uint32_t x = state ^ 0x9E3779B9u;
    x ^= (uint32_t)insn->opcode + ((uint32_t)insn->flags << 7);
    x ^= ((uint32_t)insn->dst << 11) ^ ((uint32_t)insn->srcA << 17) ^ ((uint32_t)insn->srcB << 23);
    x ^= (uint32_t)insn->operand + ((uint32_t)insn->canonical_opcode << 3) + ((uint32_t)insn->original_opcode << 19);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    return x ^ (x >> 16);
}

static int js_vm_folded_fusion_second_allowed(jint canonical_second);
static int js_vm_folded_compare_builder_allowed(jint canonical_first) {
    switch (canonical_first) {
        case JS_VM_LCMP: case JS_VM_FCMPL: case JS_VM_FCMPG: case JS_VM_DCMPL: case JS_VM_DCMPG:
            return 1;
        default:
            return 0;
    }
}

static int js_vm_folded_predicate_branch_allowed(jint canonical_second) {
    switch (canonical_second) {
        case JS_VM_IFEQ: case JS_VM_IFNE: case JS_VM_IFLT: case JS_VM_IFGE: case JS_VM_IFGT: case JS_VM_IFLE:
            return 1;
        default:
            return 0;
    }
}

static uint32_t js_vbc4_rotl32(uint32_t value, int bits);
JS_HIDDEN void js_vbc4_wipe_volatile(void *ptr, size_t len);

static int js_vm_append_folded_super_insn(js_vm_program *p, jint first_opcode, jint second_opcode, jint first_operand) {
    jint canonical_first = js_vm_canonical_opcode(first_opcode);
    jint canonical_second = js_vm_canonical_opcode(second_opcode);
    if (canonical_first == JS_VM_ICONST || canonical_first == JS_VM_BIPUSH || canonical_first == JS_VM_SIPUSH) {
        if (!js_vm_folded_fusion_second_allowed(canonical_second)) return 0;
        if (!js_vm_append_resident_insn(p, canonical_first, 1, first_operand)) return 0;
        return js_vm_append_resident_insn(p, canonical_second, 0, 0);
    }
    if (js_vm_folded_compare_builder_allowed(canonical_first)) {
        if (!js_vm_folded_predicate_branch_allowed(canonical_second)) return 0;
        if (!js_vm_append_resident_insn(p, canonical_first, 0, 0)) return 0;
        return js_vm_append_resident_insn(p, canonical_second, 1, first_operand);
    }
    return 0;
}
static int js_vm_reg_program_append(js_vm_program *p, jint opcode, jint flags, jint dst, jint srcA, jint srcB, jint operand, jint canonical_opcode, jint original_opcode) {
    if (!p) return 0;
    js_vm_reg_insn *grown = (js_vm_reg_insn*)realloc(p->reg_program.insns, (size_t)(p->reg_program.insn_count + 1) * sizeof(js_vm_reg_insn));
    if (!grown) return 0;
    p->reg_program.insns = grown;
    js_vm_reg_insn *slot = &p->reg_program.insns[p->reg_program.insn_count];
    memset(slot, 0, sizeof(*slot));
    slot->opcode = opcode;
    slot->flags = flags;
    slot->dst = dst;
    slot->srcA = srcA;
    slot->srcB = srcB;
    slot->operand = operand;
    slot->canonical_opcode = canonical_opcode;
    slot->original_opcode = original_opcode;
    if ((flags & 0x0002) != 0) p->reg_program.super_count++;
    p->reg_program.fold_digest = js_vm_reg_fold_step(p->reg_program.fold_digest, slot);
    p->reg_program.insn_count++;
    return 1;
}
static uint32_t js_vbc4_nested_mix(uint32_t seed, uint32_t profile, uint32_t block_id, uint32_t row_index, uint32_t slot, uint32_t dialect) {
    uint32_t x = seed ^ profile ^ dialect ^ (block_id * 0x045D9F3Bu) ^
        (row_index * 0x7FEB352Du) ^ (slot * 0x846CA68Bu);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 13;
    x *= 0x846CA68Bu;
    return x ^ (x >> 16);
}

static uint32_t js_vbc4_nested_dialect(uint32_t seed, uint32_t profile, uint32_t block_id, uint32_t row_count) {
    uint32_t dialect_seed = js_vbc4_rotl32(seed, 9) ^ js_vbc4_rotl32(profile, 3);
    return js_vbc4_nested_mix(seed, profile, block_id, row_count, 0x23u, dialect_seed);
}

static uint32_t js_vbc4_nested_row_checksum(uint32_t seed, uint32_t profile, uint32_t block_id, uint32_t row_index, uint32_t dialect, const uint32_t fields[6]) {
    uint32_t x = js_vbc4_nested_mix(seed, profile, block_id, row_index, JS_VBC4_NESTED_COMMIT_SLOT, dialect);
    for (uint32_t index = 0; index < JS_VBC4_NESTED_FIELD_COUNT; index++) {
        x = js_vbc4_nested_mix(x ^ fields[index], profile, block_id, row_index, index + 0x91u, dialect);
    }
    return x;
}

static void js_vm_write_u2_be(unsigned char *out, int *pos, uint32_t value) {
    out[(*pos)++] = (unsigned char)((value >> 8) & 0xFFu);
    out[(*pos)++] = (unsigned char)(value & 0xFFu);
}

static void js_vm_write_u4_be(unsigned char *out, int *pos, uint32_t value) {
    out[(*pos)++] = (unsigned char)((value >> 24) & 0xFFu);
    out[(*pos)++] = (unsigned char)((value >> 16) & 0xFFu);
    out[(*pos)++] = (unsigned char)((value >> 8) & 0xFFu);
    out[(*pos)++] = (unsigned char)(value & 0xFFu);
}

JS_PROTECTED static int js_vm_decode_nested_register_block(
    const unsigned char *block,
    int block_len,
    uint32_t build_seed,
    int logical_id,
    unsigned char **out_block,
    uint32_t *out_len,
    uint32_t *out_profile
) {
    int pos = 0;
    unsigned int register_count = 0, magic = 0, version = 0, row_count = 0, micro_count = 0;
    uint32_t profile = 0, dialect = 0, expected_dialect = 0;
    if (out_block) *out_block = NULL;
    if (out_len) *out_len = 0;
    if (out_profile) *out_profile = 0;
    if (!block || block_len <= 0 || !out_block || !out_len || !out_profile) return 0;
    if (!js_vm_read_u2(block, block_len, &pos, &register_count)) return 0;
    if (!js_vm_read_u2(block, block_len, &pos, &magic) || magic != JS_VBC4_NESTED_MAGIC) return 0;
    if (!js_vm_read_u2(block, block_len, &pos, &version) || version != JS_VBC4_NESTED_VERSION) return 0;
    if (!js_vm_read_u2(block, block_len, &pos, &row_count) || row_count == 0) return 0;
    if (!js_vm_read_u4(block, block_len, &pos, &profile) || profile == 0u) return 0;
    if (!js_vm_read_u4(block, block_len, &pos, &dialect)) return 0;
    expected_dialect = js_vbc4_nested_dialect(build_seed, profile, (uint32_t)logical_id, row_count);
    if (dialect != expected_dialect) return 0;
    if (!js_vm_read_u2(block, block_len, &pos, &micro_count)) return 0;
    if (micro_count != row_count * JS_VBC4_NESTED_MICROS_PER_ROW) return 0;
    uint32_t plain_len = 6u + row_count * 14u;
    unsigned char *plain = (unsigned char*)calloc((size_t)plain_len, 1u);
    if (!plain) return 0;
    int out_pos = 0;
    js_vm_write_u2_be(plain, &out_pos, register_count);
    js_vm_write_u2_be(plain, &out_pos, row_count);
    for (uint32_t row = 0; row < row_count; row++) {
        uint32_t fields[6] = {0, 0, 0, 0, 0, 0};
        uint32_t seen = 0u;
        for (uint32_t slot = 0; slot < JS_VBC4_NESTED_FIELD_COUNT; slot++) {
            unsigned int raw_opcode = 0, encoded_field = 0;
            uint32_t encoded_value = 0;
            uint32_t mix = js_vbc4_nested_mix(build_seed, profile, (uint32_t)logical_id, row, slot, dialect);
            uint32_t expected_opcode = JS_VBC4_NESTED_FIELD_OPCODE_BASE | (mix & 0x0FFFu);
            if (!js_vm_read_u2(block, block_len, &pos, &raw_opcode)) goto fail;
            if (!js_vm_read_u2(block, block_len, &pos, &encoded_field)) goto fail;
            if (!js_vm_read_u4(block, block_len, &pos, &encoded_value)) goto fail;
            if ((uint32_t)raw_opcode != expected_opcode) goto fail;
            uint32_t field = ((uint32_t)encoded_field ^ ((mix >> 16) & 0xFFFFu)) & 0xFFFFu;
            if (field >= JS_VBC4_NESTED_FIELD_COUNT || (seen & (1u << field)) != 0u) goto fail;
            seen |= 1u << field;
            fields[field] = encoded_value ^ js_vbc4_nested_mix(build_seed, profile, (uint32_t)logical_id, row, slot + 0x51u, dialect);
        }
        unsigned int commit_opcode = 0, commit_row = 0;
        uint32_t checksum = 0;
        uint32_t commit_mix = js_vbc4_nested_mix(build_seed, profile, (uint32_t)logical_id, row, JS_VBC4_NESTED_COMMIT_SLOT, dialect);
        if (seen != ((1u << JS_VBC4_NESTED_FIELD_COUNT) - 1u)) goto fail;
        if (!js_vm_read_u2(block, block_len, &pos, &commit_opcode)) goto fail;
        if (!js_vm_read_u2(block, block_len, &pos, &commit_row)) goto fail;
        if (!js_vm_read_u4(block, block_len, &pos, &checksum)) goto fail;
        if ((uint32_t)commit_opcode != (JS_VBC4_NESTED_COMMIT_OPCODE_BASE | (commit_mix & 0x0FFFu))) goto fail;
        if ((((uint32_t)commit_row ^ ((commit_mix >> 16) & 0xFFFFu)) & 0xFFFFu) != row) goto fail;
        if (checksum != js_vbc4_nested_row_checksum(build_seed, profile, (uint32_t)logical_id, row, dialect, fields)) goto fail;
        js_vm_write_u2_be(plain, &out_pos, fields[0]);
        js_vm_write_u2_be(plain, &out_pos, fields[1]);
        js_vm_write_u2_be(plain, &out_pos, fields[2]);
        js_vm_write_u2_be(plain, &out_pos, fields[3]);
        js_vm_write_u2_be(plain, &out_pos, fields[4]);
        js_vm_write_u4_be(plain, &out_pos, fields[5]);
    }
    if (pos != block_len || out_pos + 2 != (int)plain_len) goto fail;
    js_vm_write_u2_be(plain, &out_pos, 0u);
    *out_block = plain;
    *out_len = plain_len;
    *out_profile = profile;
    return 1;
fail:
    js_vbc4_wipe_volatile(plain, (size_t)plain_len);
    free(plain);
    return 0;
}
static int js_vm_same_loader(JNIEnv *env, jobject left, jobject right) {
    if (!left && !right) return 1;
    if (!left || !right) return 0;
    return (*env)->IsSameObject(env, left, right);
}

static uint32_t js_vbc4_rotl32(uint32_t value, int bits) { int sh = bits & 31; return sh == 0 ? value : (value << sh) | (value >> (32 - sh)); }

#ifndef JS_VBC4_BUILD_KEY_GENERATED
#error "VBC4 build root key must be generated into native_secrets.inc before compiling js_vm_core.c"
#endif
#ifndef JS_VBC4_DISPATCH_MIX_A
#define JS_VBC4_DISPATCH_MIX_A 0x9E3779B9u
#endif
#ifndef JS_VBC4_DISPATCH_MIX_B
#define JS_VBC4_DISPATCH_MIX_B 0x85EBCA6Bu
#endif
#ifndef JS_VBC4_DISPATCH_MIX_C
#define JS_VBC4_DISPATCH_MIX_C 0xD1B54A32u
#endif
#ifndef JS_VBC4_DISPATCH_STEP_MASK
#define JS_VBC4_DISPATCH_STEP_MASK 15
#endif

/* VBC4 master material is reconstructed only for the HMAC call that needs it.
 * No global plaintext key or cached HMAC pads are kept resident after JNI load. */
static void js_vbc4_copy_scoped_master_key(unsigned char out[32]) {
    JS_VBC4_COPY_SCOPED_MASTER_KEY(out);
}

/* ---- Item #4: load-time decrypt of the protected code section ----
 * Embedded keystream seed (shared with the build-time PE patcher). Generated per
 * build into native_secrets.inc; a weak fallback keeps a non-patched dev build
 * loadable (the seal marker still gates whether decryption runs at all). */
#ifndef JS_PROTECTED_SECTION_KEY_GENERATED
static const unsigned char JS_PROTECTED_SECTION_KEY[32] = {
    0x6A,0x73,0x78,0x2D,0x70,0x72,0x6F,0x74,0x65,0x63,0x74,0x2D,0x6B,0x65,0x79,0x30,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
};
#endif

JS_HIDDEN const unsigned char* js_protected_section_key(int *len) {
    if (len) *len = (int)sizeof(JS_PROTECTED_SECTION_KEY);
    return JS_PROTECTED_SECTION_KEY;
}


JS_PROTECTED static void js_hmac_sha256_with_key(const unsigned char *key, int key_len, const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]) {
    unsigned char inner_hash[32];
    unsigned char key_block[64];
    unsigned char dyn_inner[64];
    unsigned char dyn_outer[64];
    memset(key_block, 0, sizeof(key_block));
    if (key_len > 64) {
        js_sha256_ctx key_ctx;
        js_sha256_init(&key_ctx);
        js_sha256_update(&key_ctx, key, key_len);
        js_sha256_final(&key_ctx, key_block);
    } else if (key && key_len > 0) {
        memcpy(key_block, key, (size_t)key_len);
    }
    for (int index = 0; index < 64; index++) {
        dyn_inner[index] = (unsigned char)(key_block[index] ^ 0x36u);
        dyn_outer[index] = (unsigned char)(key_block[index] ^ 0x5Cu);
    }
    js_sha256_ctx ctx;
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, dyn_inner, 64);
    for (int index = 0; index < part_count; index++) js_sha256_update(&ctx, parts[index], part_lens[index]);
    js_sha256_final(&ctx, inner_hash);
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, dyn_outer, 64);
    js_sha256_update(&ctx, inner_hash, 32);
    js_sha256_final(&ctx, out);
    js_vbc4_wipe_volatile(inner_hash, sizeof(inner_hash));
    js_vbc4_wipe_volatile(key_block, sizeof(key_block));
    js_vbc4_wipe_volatile(dyn_inner, sizeof(dyn_inner));
    js_vbc4_wipe_volatile(dyn_outer, sizeof(dyn_outer));
}

static void js_vbc4_session_integrity_material(unsigned char out[32]) {
    static const unsigned char label[] = "vbc4-session-integrity";
    unsigned char base_key[32];
    unsigned char entry_integrity[4];
    js_sha256_ctx ctx;
    js_vbc4_copy_scoped_master_key(base_key);
    js_vm_write_clean_entry_integrity_bytes(entry_integrity);
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, label, (int)(sizeof(label) - 1));
    js_sha256_update(&ctx, base_key, (int)sizeof(base_key));
    unsigned char layout_digest[32];
    for (int i = 0; i < 32; i++) layout_digest[i] = JS_VBC4_LAYOUT_DIGEST_AT(i);
    js_sha256_update(&ctx, layout_digest, 32);
    js_vbc4_wipe_volatile(layout_digest, sizeof(layout_digest));
    js_sha256_update(&ctx, entry_integrity, (int)sizeof(entry_integrity));
    js_sha256_final(&ctx, out);
    js_vbc4_wipe_volatile(base_key, sizeof(base_key));
    js_vbc4_wipe_volatile(entry_integrity, sizeof(entry_integrity));
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
}
static void js_vbc4_hmac_with_scoped_master_key(const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]) {
    unsigned char session_material[32];
    unsigned char scoped_key[32];
    js_vbc4_session_integrity_material(session_material);
    js_hmac_sha256_with_key(session_material, 32, parts, part_lens, part_count, scoped_key);
    js_hmac_sha256_with_key(scoped_key, 32, parts, part_lens, part_count, out);
    js_vbc4_wipe_volatile(session_material, sizeof(session_material));
    js_vbc4_wipe_volatile(scoped_key, sizeof(scoped_key));
}


static void js_write_be32_tmp(unsigned char out[4], uint32_t value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static int js_vbc4_hmac_sha256(const unsigned char *data, int len, int seed, unsigned char out[32]) {
    unsigned char seed_bytes[4];
    js_write_be32_tmp(seed_bytes, (uint32_t)seed);
    const unsigned char *parts[2] = { seed_bytes, data };
    int lens[2] = { 4, len };
    js_vbc4_hmac_with_scoped_master_key(parts, lens, 2, out);
    return 32;
}

static int js_vbc4_hmac_sha256_with_nonce(const unsigned char *data, int len, int seed, const unsigned char nonce[16], unsigned char out[32]) {
    unsigned char seed_bytes[4];
    js_write_be32_tmp(seed_bytes, (uint32_t)seed);
    const unsigned char *parts[3] = { seed_bytes, nonce, data };
    int lens[3] = { 4, 16, len };
    js_vbc4_hmac_with_scoped_master_key(parts, lens, 3, out);
    return 32;
}

static void js_vbc4_hmac_sha256_parts(int seed, const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]) {
    unsigned char seed_bytes[4];
    const unsigned char *all_parts[8];
    int all_lens[8];
    if (part_count > 7) part_count = 7;
    js_write_be32_tmp(seed_bytes, (uint32_t)seed);
    all_parts[0] = seed_bytes;
    all_lens[0] = 4;
    for (int index = 0; index < part_count; index++) {
        all_parts[index + 1] = parts[index];
        all_lens[index + 1] = part_lens[index];
    }
    js_vbc4_hmac_with_scoped_master_key(all_parts, all_lens, part_count + 1, out);
}

static int js_vbc4_unwrap_seed(const unsigned char nonce[16], const unsigned char wrapped_seed[16], const unsigned char *state_binding, int state_binding_len, int *out_seed) {
    static const unsigned char wrap_label[] = "vbc4-seed-wrap";
    static const unsigned char token_label[] = "vbc4-seed-token";
    const unsigned char empty_binding[] = "";
    unsigned char mask[32];
    unsigned char token[32];
    unsigned char seed_bytes[4];
    int seed;
    if (!nonce || !wrapped_seed || !out_seed) return 0;
    if (!state_binding || state_binding_len < 0) { state_binding = empty_binding; state_binding_len = 0; }
    const unsigned char *wrap_parts[3] = { nonce, state_binding, wrap_label };
    int wrap_lens[3] = { 16, state_binding_len, (int)(sizeof(wrap_label) - 1) };
    js_vbc4_hmac_sha256_parts(0, wrap_parts, wrap_lens, 3, mask);
    for (int i = 0; i < 4; i++) seed_bytes[i] = (unsigned char)(wrapped_seed[i] ^ mask[i]);
    seed = (int)(((uint32_t)seed_bytes[0] << 24) | ((uint32_t)seed_bytes[1] << 16) | ((uint32_t)seed_bytes[2] << 8) | (uint32_t)seed_bytes[3]);
    const unsigned char *token_parts[3] = { nonce, state_binding, token_label };
    int token_lens[3] = { 16, state_binding_len, (int)(sizeof(token_label) - 1) };
    js_vbc4_hmac_sha256_parts(seed, token_parts, token_lens, 3, token);
    int diff = 0;
    for (int i = 0; i < 12; i++) diff |= (int)(wrapped_seed[4 + i] ^ token[i]);
    js_vbc4_wipe_volatile(mask, sizeof(mask));
    js_vbc4_wipe_volatile(token, sizeof(token));
    js_vbc4_wipe_volatile(seed_bytes, sizeof(seed_bytes));
    if (diff != 0) return 0;
    *out_seed = seed;
    return 1;
}

static uint32_t js_vbc4_key_id(int seed, const unsigned char nonce[16]) {
    static const unsigned char label[] = "vbc4-key-id";
    unsigned char digest[32];
    const unsigned char *parts[2] = { nonce, label };
    int lens[2] = { 16, (int)(sizeof(label) - 1) };
    js_vbc4_hmac_sha256_parts(seed, parts, lens, 2, digest);
    uint32_t key_id = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) | ((uint32_t)digest[2] << 8) | (uint32_t)digest[3];
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return key_id;
}

static unsigned char js_vbc4_opcode_unmask(int build_seed, int insn_index) {
    static const unsigned char label[] = "vbc4-opcode";
    unsigned char sec_bytes[4], idx_bytes[4], idx2_bytes[4];
    js_write_be32_tmp(sec_bytes, 7u);
    js_write_be32_tmp(idx_bytes, (uint32_t)insn_index);
    js_write_be32_tmp(idx2_bytes, (uint32_t)insn_index);
    const unsigned char *parts[4] = { sec_bytes, idx_bytes, idx2_bytes, label };
    int lens[4] = { 4, 4, 4, 11 };
    unsigned char digest[32];
    js_vbc4_hmac_sha256_parts(build_seed, parts, lens, 4, digest);
    unsigned char mask = digest[0];
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return mask;
}

static uint32_t js_vbc4_exception_token(int build_seed, int exception_index) {
    static const unsigned char label[] = "vbc4-exception-token";
    unsigned char idx_bytes[4];
    js_write_be32_tmp(idx_bytes, (uint32_t)exception_index);
    const unsigned char *parts[2] = { idx_bytes, label };
    int lens[2] = { 4, (int)(sizeof(label) - 1) };
    unsigned char digest[32];
    js_vbc4_hmac_sha256_parts(build_seed, parts, lens, 2, digest);
    uint32_t token = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) | ((uint32_t)digest[2] << 8) | (uint32_t)digest[3];
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return token;
}

static uint32_t js_vbc4_exception_mask(int build_seed, int exception_index, int field_index, uint32_t token) {
    static const unsigned char label[] = "vbc4-exception-mask";
    unsigned char idx_bytes[4], field_bytes[4], token_bytes[4];
    js_write_be32_tmp(idx_bytes, (uint32_t)exception_index);
    js_write_be32_tmp(field_bytes, (uint32_t)field_index);
    js_write_be32_tmp(token_bytes, token);
    const unsigned char *parts[4] = { idx_bytes, field_bytes, token_bytes, label };
    int lens[4] = { 4, 4, 4, (int)(sizeof(label) - 1) };
    unsigned char digest[32];
    js_vbc4_hmac_sha256_parts(build_seed, parts, lens, 4, digest);
    uint32_t mask = (((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) | ((uint32_t)digest[2] << 8) | (uint32_t)digest[3]) & 0xFFFFu;
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return mask;
}


static void js_secret_aes_ctr_decode(const unsigned char *enc, int len, int idx, char *out) {
    if (!enc || !out || len < 0) return;
    unsigned char counter[16];
    unsigned char stream[16];
    memcpy(counter, JS_SECRET_AES_IV, sizeof(counter));
    int carry = idx;
    for (int pos = 15; pos >= 0 && carry != 0; pos--) {
        unsigned int sum = (unsigned int)counter[pos] + (unsigned int)(carry & 0xFF);
        counter[pos] = (unsigned char)(sum & 0xFFu);
        carry = (carry >> 8) + (int)(sum >> 8);
    }
    int offset = 0;
    while (offset < len) {
        js_aes128_encrypt_block(counter, JS_SECRET_AES_KEY, stream);
        int chunk = len - offset < 16 ? len - offset : 16;
        for (int i = 0; i < chunk; i++) out[offset + i] = (char)(enc[offset + i] ^ stream[i]);
        offset += chunk;
        js_ctr_inc(counter);
    }
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(stream, sizeof(stream));
}

static const char* js_secret_get(int id) {
    if (js_secret_buf_dirty) {
        volatile unsigned char *p = (volatile unsigned char *)js_secret_buf;
        for (int i = 0; i < (int)sizeof(js_secret_buf); i++) p[i] = 0;
    }
    switch (id) {
        case 0: JS_SECRET_DECRYPT(SECURITY_EXCEPTION_CLASS, js_secret_buf); break;
        case 1: JS_SECRET_DECRYPT(MANAGEMENT_FACTORY_CLASS, js_secret_buf); break;
        case 2: JS_SECRET_DECRYPT(THREAD_CLASS, js_secret_buf); break;
        case 3: JS_SECRET_DECRYPT(SYSTEM_CLASS, js_secret_buf); break;
        case 4: JS_SECRET_DECRYPT(RUNTIME_CLASS, js_secret_buf); break;
        case 5: JS_SECRET_DECRYPT(STACK_TRACE_ELEMENT_CLASS, js_secret_buf); break;
        case 6: JS_SECRET_DECRYPT(ARRAY_LIST_CLASS, js_secret_buf); break;
        case 7: JS_SECRET_DECRYPT(IOEXCEPTION_CLASS, js_secret_buf); break;
        case 8: JS_SECRET_DECRYPT(GET_INPUT_ARGS, js_secret_buf); break;
        case 9: JS_SECRET_DECRYPT(GET_STACK_TRACE, js_secret_buf); break;
        case 10: JS_SECRET_DECRYPT(GET_CLASS_NAME, js_secret_buf); break;
        case 11: JS_SECRET_DECRYPT(HASH_CODE, js_secret_buf); break;
        case 12: JS_SECRET_DECRYPT(GET_CLASS_LOADER, js_secret_buf); break;
        case 13: JS_SECRET_DECRYPT(LOAD_CLASS, js_secret_buf); break;
        case 14: JS_SECRET_DECRYPT(FOR_NAME, js_secret_buf); break;
        case 15: JS_SECRET_DECRYPT(GET_RESOURCEAsStream, js_secret_buf); break;
        default: js_secret_buf[0] = 0; break;
    }
    js_secret_buf_dirty = 1;
    return js_secret_buf;
}
static void js_vbc4_aes_material(int seed, const unsigned char nonce[16], int section, int block_id, unsigned char key[16], unsigned char iv[16]) {
    static const unsigned char key_label[] = "vbc4-aes-key";
    static const unsigned char iv_label[] = "vbc4-aes-iv";
    unsigned char section_bytes[4], block_bytes[4], digest[32];
    js_write_be32_tmp(section_bytes, (uint32_t)section);
    js_write_be32_tmp(block_bytes, (uint32_t)block_id);
    const unsigned char *key_parts[4] = { nonce, section_bytes, block_bytes, key_label };
    int key_lens[4] = { 16, 4, 4, (int)(sizeof(key_label) - 1) };
    js_vbc4_hmac_sha256_parts(seed, key_parts, key_lens, 4, digest);
    memcpy(key, digest, 16);
    const unsigned char *iv_parts[4] = { nonce, section_bytes, block_bytes, iv_label };
    int iv_lens[4] = { 16, 4, 4, (int)(sizeof(iv_label) - 1) };
    js_vbc4_hmac_sha256_parts(seed, iv_parts, iv_lens, 4, digest);
    memcpy(iv, digest, 16);
    js_vbc4_wipe_volatile(digest, sizeof(digest));
}

/* Block-level decrypt entrypoint used by the VBC4 interpreter dispatch. */
JS_HIDDEN void js_vbc4_decrypt_block(unsigned char *buf, int len, int seed, const unsigned char nonce[16], int section, int block_id) {
    unsigned char key[16];
    unsigned char counter[16];
    unsigned char stream[16];
    js_vbc4_aes_material(seed, nonce, section, block_id, key, counter);
    int offset = 0;
    while (offset < len) {
        js_aes128_encrypt_block(counter, key, stream);
        int chunk = len - offset < 16 ? len - offset : 16;
        for (int index = 0; index < chunk; index++) buf[offset + index] ^= stream[index];
        offset += chunk;
        js_ctr_inc(counter);
    }
    js_vbc4_wipe_volatile(key, sizeof(key));
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(stream, sizeof(stream));
}

JS_HIDDEN void js_vbc4_decrypt_block_with_material(unsigned char *buf, int len, const unsigned char key[16], const unsigned char iv[16]) {
    unsigned char counter[16];
    unsigned char stream[16];
    memcpy(counter, iv, 16);
    int offset = 0;
    while (offset < len) {
        js_aes128_encrypt_block(counter, key, stream);
        int chunk = len - offset < 16 ? len - offset : 16;
        for (int index = 0; index < chunk; index++) buf[offset + index] ^= stream[index];
        offset += chunk;
        js_ctr_inc(counter);
    }
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(stream, sizeof(stream));
}

static uint32_t js_read_le32_runtime(const unsigned char *data, int offset) {
    return ((uint32_t)data[offset]) | ((uint32_t)data[offset + 1] << 8) | ((uint32_t)data[offset + 2] << 16) | ((uint32_t)data[offset + 3] << 24);
}

static uint32_t js_read_be32_runtime(const unsigned char *data, int offset) {
    return ((uint32_t)data[offset] << 24) | ((uint32_t)data[offset + 1] << 16) | ((uint32_t)data[offset + 2] << 8) | (uint32_t)data[offset + 3];
}

static uint32_t js_read_le16_runtime(const unsigned char *data, int offset) {
    return ((uint32_t)data[offset]) | ((uint32_t)data[offset + 1] << 8);
}

static void js_runtime_hmac_sha256(const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]) {
    if (!js_runtime_resource_key_ready) { memset(out, 0, 32); return; }
    unsigned char root[32];
    js_rrk_xor_assemble(&js_runtime_resource_key_shares[0][0], JS_RRK_SHARE_COUNT, root);
    js_hmac_sha256_with_key(root, 32, parts, part_lens, part_count, out);
    js_vbc4_wipe_volatile(root, sizeof(root));
}

static void js_runtime_resource_aes_ctr(unsigned char *buf, int len, const unsigned char nonce[16], int kind_id, int variant_id, int layer_count) {
    static const unsigned char key_label[] = "jsrp-aes-key";
    static const unsigned char iv_label[] = "jsrp-aes-iv";
    unsigned char kind_bytes[4], variant_bytes[4], layer_bytes[4], digest[32], key[16], counter[16], stream[16];
    js_write_be32_tmp(kind_bytes, (uint32_t)kind_id);
    js_write_be32_tmp(variant_bytes, (uint32_t)variant_id);
    js_write_be32_tmp(layer_bytes, (uint32_t)layer_count);
    const unsigned char *key_parts[5] = { key_label, nonce, kind_bytes, variant_bytes, layer_bytes };
    int key_lens[5] = { (int)(sizeof(key_label) - 1), 16, 4, 4, 4 };
    js_runtime_hmac_sha256(key_parts, key_lens, 5, digest);
    memcpy(key, digest, 16);
    const unsigned char *iv_parts[5] = { iv_label, nonce, kind_bytes, variant_bytes, layer_bytes };
    int iv_lens[5] = { (int)(sizeof(iv_label) - 1), 16, 4, 4, 4 };
    js_runtime_hmac_sha256(iv_parts, iv_lens, 5, digest);
    memcpy(counter, digest, 16);
    int offset = 0;
    while (offset < len) {
        js_aes128_encrypt_block(counter, key, stream);
        int chunk = len - offset < 16 ? len - offset : 16;
        for (int i = 0; i < chunk; i++) buf[offset + i] ^= stream[i];
        offset += chunk;
        js_ctr_inc(counter);
    }
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    js_vbc4_wipe_volatile(key, sizeof(key));
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(stream, sizeof(stream));
}

static int js_runtime_resource_ct_equal(const unsigned char *a, const unsigned char *b, int len) {
    unsigned char diff = 0;
    if (!a || !b || len < 0) return 0;
    for (int i = 0; i < len; i++) diff = (unsigned char)(diff | (unsigned char)(a[i] ^ b[i]));
    return diff == 0;
}

static void js_runtime_sha256(const unsigned char *data, int len, unsigned char out[32]) {
    js_sha256_ctx ctx;
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, data, len);
    js_sha256_final(&ctx, out);
}

static void js_runtime_resource_aes_ctr_domains(unsigned char *buf, int len, const unsigned char nonce[16], uint32_t kind_id, uint32_t variant_id, uint32_t layer_count) {
    int kind_arg = (int)kind_id;
    int variant_arg = (int)variant_id;
    int layer_arg = (int)layer_count;
    js_runtime_resource_aes_ctr(buf, len, nonce, kind_arg, variant_arg, layer_arg);
}

static unsigned char* js_runtime_resource_decode_current_owned(const unsigned char *raw, int raw_len, int *out_len) {
    static const unsigned char auth_label[] = "jsrp-auth-v2";
    if (raw_len < 154 || raw[raw_len - 1] != 32) return NULL;
    const unsigned char *nonce = raw + 5;
    uint32_t metadata_len = js_read_le16_runtime(raw, 21);
    uint32_t mac_len = js_read_le16_runtime(raw, 23);
    if (metadata_len != 96 || mac_len != 32) return NULL;
    int metadata_offset = 25;
    int body_offset = metadata_offset + (int)metadata_len;
    if (body_offset + 33 > raw_len) return NULL;
    int tag_offset = raw_len - 33;
    unsigned char expected[32];
    const unsigned char *parts[3] = { auth_label, nonce, raw };
    int lens[3] = { (int)(sizeof(auth_label) - 1), 16, tag_offset };
    js_runtime_hmac_sha256(parts, lens, 3, expected);
    if (!js_runtime_resource_ct_equal(raw + tag_offset, expected, 32)) {
        js_vbc4_wipe_volatile(expected, sizeof(expected));
        return NULL;
    }
    js_vbc4_wipe_volatile(expected, sizeof(expected));

    unsigned char metadata[96];
    memcpy(metadata, raw + metadata_offset, sizeof(metadata));
    js_runtime_resource_aes_ctr_domains(metadata, (int)sizeof(metadata), nonce, 0, 0, 0);
    if (metadata[0] != 0x4Du || metadata[1] != 0x32u || metadata[2] != 1u) {
        js_vbc4_wipe_volatile(metadata, sizeof(metadata));
        return NULL;
    }
    uint32_t flags = metadata[6] & 0xFFu;
    if ((flags & 0xFEu) != 0) {
        js_vbc4_wipe_volatile(metadata, sizeof(metadata));
        return NULL;
    }
    unsigned char metadata_hash[32];
    js_runtime_sha256(metadata, 92, metadata_hash);
    if (js_read_le32_runtime(metadata, 92) != js_read_be32_runtime(metadata_hash, 0)) {
        js_vbc4_wipe_volatile(metadata_hash, sizeof(metadata_hash));
        js_vbc4_wipe_volatile(metadata, sizeof(metadata));
        return NULL;
    }
    js_vbc4_wipe_volatile(metadata_hash, sizeof(metadata_hash));

    uint32_t kind_id = metadata[3] & 0xFFu;
    uint32_t layer_count = metadata[4] & 0xFFu;
    uint32_t variant_id = metadata[5] & 0xFFu;
    int compressed = (flags & 1u) != 0;
    uint32_t plain_len = js_read_le32_runtime(metadata, 8);
    uint32_t stored_len = js_read_le32_runtime(metadata, 12);
    uint32_t body_len = js_read_le32_runtime(metadata, 16);
    unsigned char plain_hash[32];
    unsigned char stored_hash[32];
    memcpy(plain_hash, metadata + 28, sizeof(plain_hash));
    memcpy(stored_hash, metadata + 60, sizeof(stored_hash));
    js_vbc4_wipe_volatile(metadata, sizeof(metadata));
    if (body_len > (uint32_t)raw_len || plain_len > 0x7FFFFFFFu || stored_len > 0x7FFFFFFFu) return NULL;
    if (kind_id < 1 || kind_id > 4 || layer_count < 1 || layer_count > 7 || variant_id > 127) return NULL;
    if (body_len != stored_len || body_offset + (int)body_len != tag_offset) return NULL;
    if (!compressed && plain_len != stored_len) return NULL;

    unsigned char *stored = (unsigned char*)(body_len == 0 ? calloc(1, 1) : malloc((size_t)body_len));
    if (!stored) return NULL;
    memcpy(stored, raw + body_offset, (size_t)body_len);
    js_runtime_resource_aes_ctr_domains(stored, (int)body_len, nonce, kind_id, variant_id, layer_count);
    unsigned char digest[32];
    js_runtime_sha256(stored, (int)stored_len, digest);
    if (!js_runtime_resource_ct_equal(digest, stored_hash, 32)) {
        js_vbc4_wipe_volatile(digest, sizeof(digest));
        js_vbc4_wipe_volatile(stored, (size_t)body_len);
        free(stored);
        return NULL;
    }
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    unsigned char *plain = compressed ? js_vbc4_zstd_decompress_owned(stored, stored_len, plain_len) : stored;
    if (compressed) { js_vbc4_wipe_volatile(stored, (size_t)body_len); free(stored); }
    if (!plain) return NULL;
    js_runtime_sha256(plain, (int)plain_len, digest);
    if (!js_runtime_resource_ct_equal(digest, plain_hash, 32)) {
        js_vbc4_wipe_volatile(digest, sizeof(digest));
        js_vbc4_wipe_volatile(plain, (size_t)plain_len);
        free(plain);
        return NULL;
    }
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    if (out_len) *out_len = (int)plain_len;
    return plain;
}

static unsigned char* js_runtime_resource_decode_legacy_owned(const unsigned char *raw, int raw_len, int *out_len) {
    static const unsigned char auth_label[] = "jsrp-auth";
    if (raw_len < 73 || raw[raw_len - 1] != 32) return NULL;
    int kind_id = raw[5] & 0xFF;
    int layer_count = raw[6] & 0xFF;
    int flags = raw[7] & 0xFF;
    int compressed = (flags & 0x80) != 0;
    int variant_id = flags & 0x7F;
    if (layer_count < 1 || layer_count > 7) return NULL;
    const unsigned char *nonce = raw + 8;
    uint32_t plain_len = js_read_le32_runtime(raw, 24);
    uint32_t stored_len = js_read_le32_runtime(raw, 28);
    uint32_t body_len = js_read_le32_runtime(raw, 32);
    if (stored_len == 0 || body_len != stored_len || body_len > (uint32_t)raw_len) return NULL;
    int tag_offset = 40 + (int)body_len;
    if (tag_offset < 40 || tag_offset + 33 != raw_len) return NULL;
    unsigned char expected[32];
    const unsigned char *parts[3] = { auth_label, nonce, raw };
    int lens[3] = { (int)(sizeof(auth_label) - 1), 16, tag_offset };
    js_runtime_hmac_sha256(parts, lens, 3, expected);
    if (!js_runtime_resource_ct_equal(raw + tag_offset, expected, 32)) { js_vbc4_wipe_volatile(expected, sizeof(expected)); return NULL; }
    js_vbc4_wipe_volatile(expected, sizeof(expected));
    unsigned char *stored = (unsigned char*)malloc((size_t)body_len);
    if (!stored) return NULL;
    memcpy(stored, raw + 40, (size_t)body_len);
    js_runtime_resource_aes_ctr(stored, (int)body_len, nonce, kind_id, variant_id, layer_count);
    unsigned char *plain = compressed ? js_vbc4_zstd_decompress_owned(stored, stored_len, plain_len) : stored;
    if (compressed) { js_vbc4_wipe_volatile(stored, (size_t)body_len); free(stored); }
    if (!plain) return NULL;
    if (out_len) *out_len = (int)plain_len;
    return plain;
}

JS_HIDDEN unsigned char* js_runtime_resource_decode_owned(const unsigned char *raw, int raw_len, int *out_len) {
    if (out_len) *out_len = 0;
    if (!raw || raw_len < 6 || !js_runtime_resource_key_ready) return NULL;
    if (raw[0] != 0x4A || raw[1] != 0x53 || raw[2] != 0x52 || raw[3] != 0x50) return NULL;
    if (raw[4] == 6) return js_runtime_resource_decode_current_owned(raw, raw_len, out_len);
    if (raw[4] == 5) return js_runtime_resource_decode_legacy_owned(raw, raw_len, out_len);
    return NULL;
}


static int contains_parts(const char *s, const char *a, const char *b, const char *c) {
    char *needle = js_join_parts(a, b, c, NULL);
    int found = contains(s, needle);
    free(needle);
    return found;
}

static int starts_parts(const char *s, const char *a, const char *b, const char *c) {
    char *needle = js_join_parts(a, b, c, NULL);
    int found = starts(s, needle);
    free(needle);
    return found;
}

static void throw_sec(JNIEnv *env, const char *msg) {
    jclass c = js_jni_cache.initialized ? js_jni_cache.security_exception_class : (*env)->FindClass(env, js_secret_get(JS_SECRET_ID_SECURITY_EXCEPTION_CLASS));
    if (c) (*env)->ThrowNew(env, c, msg);
}

struct ia_result { const char **args; int count; };
static struct ia_result get_input_args(JNIEnv *env) {
    struct ia_result r = {NULL, 0};
    jclass mf = (*env)->FindClass(env, js_secret_get(JS_SECRET_ID_MANAGEMENT_FACTORY_CLASS));
    if (!mf) { js_clear_pending_exception(env); return r; }
    jmethodID m = (*env)->GetStaticMethodID(env, mf, "getRuntimeMXBean", "()Ljava/lang/management/RuntimeMXBean;");
    if (!m) { js_clear_pending_exception(env); return r; }
    jobject mb = (*env)->CallStaticObjectMethod(env, mf, m);
    if (js_pending_exception(env) || !mb) { js_clear_pending_exception(env); return r; }
    jclass rc = (*env)->GetObjectClass(env, mb);
    jmethodID gl = rc ? (*env)->GetMethodID(env, rc, "getInputArguments", "()Ljava/util/List;") : NULL;
    if (js_pending_exception(env) || !gl) { js_clear_pending_exception(env); return r; }
    jobject lst = (*env)->CallObjectMethod(env, mb, gl);
    if (js_pending_exception(env) || !lst) { js_clear_pending_exception(env); return r; }
    jclass lc = (*env)->GetObjectClass(env, lst);
    jmethodID sz = lc ? (*env)->GetMethodID(env, lc, "size", "()I") : NULL;
    jmethodID gt = lc ? (*env)->GetMethodID(env, lc, "get", "(I)Ljava/lang/Object;") : NULL;
    if (js_pending_exception(env) || !sz || !gt) { js_clear_pending_exception(env); return r; }
    jint len = (*env)->CallIntMethod(env, lst, sz);
    if (js_pending_exception(env) || len <= 0) { js_clear_pending_exception(env); return r; }
    r.count = (int)len;
    r.args = (const char**)calloc((size_t)len, sizeof(const char*));
    if (!r.args) { r.count = 0; return r; }
    for (jint i = 0; i < len; i++) {
        jstring s = (jstring)(*env)->CallObjectMethod(env, lst, gt, i);
        if (js_pending_exception(env)) { js_clear_pending_exception(env); continue; }
        if (s) {
            const char *tmp = (*env)->GetStringUTFChars(env, s, NULL);
            if (tmp) {
                r.args[i] = js_strdup(tmp);
                (*env)->ReleaseStringUTFChars(env, s, tmp);
            }
        }
    }
    return r;
}

static void free_input_args(JNIEnv *env, struct ia_result *ia) {
    (void)env;
    if (!ia) return;
    for (int i = 0; i < ia->count; i++) free((void*)ia->args[i]);
    free(ia->args);
    ia->args = NULL;
    ia->count = 0;
}

struct sc_result { const char **names; int count; };
static struct sc_result get_stack_classes(JNIEnv *env) {
    struct sc_result r = {NULL, 0};
    jclass tc = js_jni_cache.initialized ? js_jni_cache.thread_class : (*env)->FindClass(env, js_secret_get(JS_SECRET_ID_THREAD_CLASS));
    if (!tc) { js_clear_pending_exception(env); return r; }
    jmethodID ct = js_jni_cache.initialized ? js_jni_cache.thread_current_thread : (*env)->GetStaticMethodID(env, tc, "currentThread", "()Ljava/lang/Thread;");
    if (!ct) { js_clear_pending_exception(env); return r; }
    jobject t = (*env)->CallStaticObjectMethod(env, tc, ct);
    if (js_pending_exception(env) || !t) { js_clear_pending_exception(env); return r; }
    jmethodID gs = (*env)->GetMethodID(env, tc, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
    if (js_pending_exception(env) || !gs) { js_clear_pending_exception(env); return r; }
    jobjectArray ea = (jobjectArray)(*env)->CallObjectMethod(env, t, gs);
    if (js_pending_exception(env) || !ea) { js_clear_pending_exception(env); return r; }
    jclass sc = (*env)->FindClass(env, js_secret_get(JS_SECRET_ID_STACK_TRACE_ELEMENT_CLASS));
    if (js_pending_exception(env) || !sc) { js_clear_pending_exception(env); return r; }
    jmethodID gcn = (*env)->GetMethodID(env, sc, "getClassName", "()Ljava/lang/String;");
    if (js_pending_exception(env) || !gcn) { js_clear_pending_exception(env); return r; }
    jsize len = (*env)->GetArrayLength(env, ea);
    if (len <= 0) return r;
    r.count = (int)len;
    r.names = (const char**)calloc((size_t)len, sizeof(const char*));
    if (!r.names) { r.count = 0; return r; }
    for (jsize i = 0; i < len; i++) {
        jobject ste = (*env)->GetObjectArrayElement(env, ea, i);
        if (js_pending_exception(env)) { js_clear_pending_exception(env); continue; }
        jstring cn = ste ? (jstring)(*env)->CallObjectMethod(env, ste, gcn) : NULL;
        if (js_pending_exception(env)) { js_clear_pending_exception(env); continue; }
        if (cn) {
            const char *tmp = (*env)->GetStringUTFChars(env, cn, NULL);
            if (tmp) {
                r.names[i] = js_strdup(tmp);
                (*env)->ReleaseStringUTFChars(env, cn, tmp);
            }
        }
    }
    return r;
}

static void free_stack_classes(JNIEnv *env, struct sc_result *sc) {
    (void)env;
    if (!sc) return;
    for (int i = 0; i < sc->count; i++) free((void*)sc->names[i]);
    free(sc->names);
    sc->names = NULL;
    sc->count = 0;
}

static const signed char b64t[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static int b64dec(const char *in, int inlen, unsigned char *out) {
    int o = 0, i = 0;
    while (i < inlen) {
        int aa = i < inlen ? b64t[(unsigned char)in[i++]] : -1;
        int bb = i < inlen ? b64t[(unsigned char)in[i++]] : -1;
        int cc = i < inlen ? b64t[(unsigned char)in[i++]] : -1;
        int dd = i < inlen ? b64t[(unsigned char)in[i++]] : -1;
        if (aa < 0 || bb < 0) break;
        if (out) out[o] = (unsigned char)((aa << 2) | (bb >> 4));
        o++;
        if (cc < 0) break;
        if (out) out[o] = (unsigned char)(((bb & 0xF) << 4) | (cc >> 2));
        o++;
        if (dd < 0) break;
        if (out) out[o] = (unsigned char)(((cc & 3) << 6) | dd);
        o++;
    }
    return o;
}

static volatile int js_runtime_guard_degraded = 0;
static volatile int js_runtime_guard_strict_path = 0;
static volatile int js_runtime_guard_log_once = 0;
static volatile uint32_t js_runtime_anti_dump_mix = 0;

JS_LOCAL void JNICALL jsn_r4(JNIEnv *env, jclass cls, jstring jpl, jclass ownerClass);

static void js_runtime_guard_response(JNIEnv *env, const char *resp, const char *reason) {
    if (!resp) return;
    if (!strcmp(resp, "log")) {
        if (!js_runtime_guard_log_once) {
            js_runtime_guard_log_once = 1;
            fprintf(stderr, "JavaShroud runtime guard detected instrumentation: %s\n", reason ? reason : "unknown");
            fflush(stderr);
        }
        return;
    }
    if (!strcmp(resp, "degrade")) {
        js_runtime_guard_degraded = 1;
        js_vm_trace_poison_seed = 0xD36D4E21u;
        return;
    }
    if (!strcmp(resp, "switch-path")) {
        js_runtime_guard_strict_path = 1;
        js_vm_trace_poison_seed = 0x51A17C0Du;
        return;
    }
    if (!strcmp(resp, "refuse")) throw_sec(env, "runtime check failed");
}

static int js_runtime_detect_input_arg_instrumentation(JNIEnv *env, int aggressive) {
    struct ia_result ia = get_input_args(env);
    int detected = 0;
    for (int i = 0; i < ia.count; i++) {
        const char *arg = ia.args[i];
        if (!arg) continue;
        if (starts(arg, "-javaagent:") || starts(arg, "-agentlib:") || starts(arg, "-agentpath:")) { detected = 1; break; }
        if (strstr(arg, "jdwp") || strstr(arg, "EnableDynamicAgentLoading") || strstr(arg, "StartAttachListener")) { detected = 1; break; }
        if (aggressive && (strstr(arg, "bytebuddy") || strstr(arg, "mockito") || strstr(arg, "jvmti"))) { detected = 1; break; }
    }
    free_input_args(env, &ia);
    return detected;
}

static int js_runtime_detect_stack_instrumentation(JNIEnv *env, int aggressive) {
    struct sc_result sc = get_stack_classes(env);
    int detected = 0;
    for (int i = 0; i < sc.count; i++) {
        const char *name = sc.names[i];
        if (!name) continue;
        if (contains_parts(name, "byte", "buddy", NULL) || contains_parts(name, "net.", "byte", "buddy")) { detected = 1; break; }
        if (aggressive && (
            contains_parts(name, "org.", "mockito", NULL) ||
            contains_parts(name, "java.", "lang.", "instrument") ||
            contains_parts(name, "Instrumentation", "Impl", NULL) ||
            contains_parts(name, "retransform", NULL, NULL) ||
            contains_parts(name, "redefine", NULL, NULL) ||
            contains_parts(name, "asm", "Class", "Visitor")
        )) { detected = 1; break; }
    }
    free_stack_classes(env, &sc);
    return detected;
}

JS_LOCAL void JNICALL
jsn_r0(JNIEnv *env, jclass cls, jstring jdl, jstring jresp) {
    (void)cls;
    const char *dl = j2c(env, jdl);
    const char *resp = j2c(env, jresp);
    if (!dl || !resp) { rls(env, jdl, dl); rls(env, jresp, resp); return; }
    int aggressive = !strcmp(dl, "aggressive");
    if (js_runtime_detect_input_arg_instrumentation(env, aggressive)) js_runtime_guard_response(env, resp, "vm-argument");
    if (!(*env)->ExceptionCheck(env) && aggressive && js_runtime_detect_stack_instrumentation(env, aggressive)) js_runtime_guard_response(env, resp, "stack-trace");
    rls(env, jdl, dl); rls(env, jresp, resp);
}

JS_LOCAL void JNICALL
jsn_r1(JNIEnv *env, jclass cls, jstring jdm, jstring jresp) {
    (void)cls; (void)jdm;
    const char *resp = j2c(env, jresp);
    if (!resp) { rls(env, jresp, resp); return; }
    struct ia_result ia = get_input_args(env);
    int ha = 0;
    for (int i = 0; i < ia.count; i++) {
        const char *arg = ia.args[i];
        if (arg && (starts(arg, "-javaagent:") || starts(arg, "-agentlib:"))) { ha = 1; break; }
    }
    free_input_args(env, &ia);
    if (ha && !strcmp(resp, "refuse")) throw_sec(env, "runtime check failed");
    rls(env, jresp, resp);
}

JS_LOCAL void JNICALL
jsn_r2(JNIEnv *env, jclass cls, jstring jresp) {
    (void)cls;
    const char *resp = j2c(env, jresp);
    if (!resp) { rls(env, jresp, resp); return; }
    struct sc_result sc = get_stack_classes(env);
    int found = 0;
    for (int i = 0; i < sc.count; i++) {
        if (sc.names[i] && (starts_parts(sc.names[i], "net.", "byte", "buddy") || contains_parts(sc.names[i], "Byte", "Buddy", "Agent"))) { found = 1; break; }
    }
    free_stack_classes(env, &sc);
    if (found && !strcmp(resp, "refuse")) throw_sec(env, "runtime check failed");
    rls(env, jresp, resp);
}

JS_LOCAL void JNICALL
jsn_r3(JNIEnv *env, jclass cls, jstring jpl) {
    jsn_r4(env, cls, jpl, NULL);
}

JS_LOCAL void JNICALL
jsn_r4(JNIEnv *env, jclass cls, jstring jpl, jclass ownerClass) {
    (void)cls;
    const char *pl = j2c(env, jpl);
    if (!pl) { rls(env, jpl, pl); return; }
    if (!strcmp(pl, "full")) {
        js_runtime_guard_strict_path = 1;
        js_runtime_anti_dump_mix ^= 0xA11D0BEEu;
    } else if (!strcmp(pl, "jni-key-hold")) {
        js_runtime_guard_degraded |= 0;
    } else if (!strcmp(pl, "field-scramble")) {
        js_runtime_guard_degraded |= 0;
    }
    if (ownerClass && js_jni_cache.initialized && js_jni_cache.class_get_name) {
        jstring name = (jstring)(*env)->CallObjectMethod(env, ownerClass, js_jni_cache.class_get_name);
        if (!(*env)->ExceptionCheck(env) && name) {
            const char *owner_name = j2c(env, name);
            if (owner_name) {
                uint32_t owner_mix = fnv1a((const unsigned char*)owner_name, (int)strlen(owner_name));
                if (!strcmp(pl, "full")) js_runtime_anti_dump_mix ^= owner_mix;
                rls(env, name, owner_name);
            }
            (*env)->DeleteLocalRef(env, name);
        } else if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
    }
    rls(env, jpl, pl);
}

JS_LOCAL jstring JNICALL
jsn_r11(JNIEnv *env, jclass cls, jbyteArray encodedBytes) {
    (void)cls;
    if (!encodedBytes) return NULL;
    jsize len = (*env)->GetArrayLength(env, encodedBytes);
    jbyte *bytes = (*env)->GetByteArrayElements(env, encodedBytes, NULL);
    if (!bytes) return NULL;
    char *buf = (char*)calloc((size_t)len + 1, 1);
    jstring result = NULL;
    if (buf) {
        memcpy(buf, bytes, (size_t)len);
        result = (*env)->NewStringUTF(env, buf);
        js_vbc4_wipe_volatile(buf, (size_t)len);
        free(buf);
    }
    (*env)->ReleaseByteArrayElements(env, encodedBytes, bytes, JNI_ABORT);
    return result ? result : (*env)->NewStringUTF(env, "");
}

JS_LOCAL jstring JNICALL
jsn_r12(JNIEnv *env, jclass cls, jstring encodedB64) {
    (void)cls;
    if (!encodedB64) return NULL;
    const char *b64 = j2c(env, encodedB64);
    if (!b64) return NULL;
    int slen = (int)strlen(b64);
    unsigned char *buf = (unsigned char*)calloc((size_t)(slen * 3 / 4 + 4), 1);
    if (!buf) { rls(env, encodedB64, b64); return NULL; }
    int actual = b64dec(b64, slen, buf);
    char *str = (char*)calloc((size_t)actual + 1, 1);
    jstring result = NULL;
    if (str) {
        memcpy(str, buf, (size_t)actual);
        result = (*env)->NewStringUTF(env, str);
        js_vbc4_wipe_volatile(str, (size_t)actual);
        free(str);
    }
    js_vbc4_wipe_volatile(buf, (size_t)(slen * 3 / 4 + 4));
    free(buf);
    rls(env, encodedB64, b64);
    return result ? result : (*env)->NewStringUTF(env, "");
}

JS_LOCAL jstring JNICALL
jsn_r13(JNIEnv *env, jclass cls, jstring encoded) {
    return jsn_r12(env, cls, encoded);
}

JS_LOCAL jstring JNICALL
jsn_r16(JNIEnv *env, jclass cls, jstring bindingSource, jstring salt) {
    (void)cls;
    const char *src = j2c(env, bindingSource);
    const char *slt = j2c(env, salt);
    char km[256];
    snprintf(km, sizeof(km), "envkey:%s:%s", src ? src : "", slt ? slt : "");
    unsigned int h = fnv1a((const unsigned char*)km, (int)strlen(km));
    char hex[32];
    snprintf(hex, sizeof(hex), "%08x", h);
    js_vbc4_wipe_volatile(km, sizeof(km));
    rls(env, bindingSource, src);
    rls(env, salt, slt);
    return (*env)->NewStringUTF(env, hex);
}

JS_LOCAL void JNICALL
jsn_r17(JNIEnv *env, jclass cls, jstring expectedToken, jstring bindingSource, jstring salt) {
    (void)cls;
    const char *tok = j2c(env, expectedToken);
    const char *src = j2c(env, bindingSource);
    const char *slt = j2c(env, salt);
    if (tok && strlen(tok) > 0) {
        char km[256];
        snprintf(km, sizeof(km), "envkey:%s:%s", src ? src : "", slt ? slt : "");
        unsigned int h = fnv1a((const unsigned char*)km, (int)strlen(km));
        char hex[32];
        snprintf(hex, sizeof(hex), "%08x", h);
        js_vbc4_wipe_volatile(km, sizeof(km));
        if (strcmp(tok, hex) != 0) throw_sec(env, "Environment binding verification failed");
    }
    rls(env, expectedToken, tok);
    rls(env, bindingSource, src);
    rls(env, salt, slt);
}

static void js_string_payload_material(int seed, int flags, int len, unsigned char key[16], unsigned char iv[16]) {
    static const unsigned char key_label[] = "js-string-aes-key";
    static const unsigned char iv_label[] = "js-string-aes-iv";
    unsigned char seed_bytes[4], flags_bytes[4], len_bytes[4], digest[32];
    js_write_be32_tmp(seed_bytes, (uint32_t)seed);
    js_write_be32_tmp(flags_bytes, (uint32_t)flags);
    js_write_be32_tmp(len_bytes, (uint32_t)len);
    const unsigned char *key_parts[4] = { key_label, seed_bytes, flags_bytes, len_bytes };
    int key_lens[4] = { (int)(sizeof(key_label) - 1), 4, 4, 4 };
    js_vbc4_hmac_with_scoped_master_key(key_parts, key_lens, 4, digest);
    memcpy(key, digest, 16);
    const unsigned char *iv_parts[4] = { iv_label, seed_bytes, flags_bytes, len_bytes };
    int iv_lens[4] = { (int)(sizeof(iv_label) - 1), 4, 4, 4 };
    js_vbc4_hmac_with_scoped_master_key(iv_parts, iv_lens, 4, digest);
    memcpy(iv, digest, 16);
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    js_vbc4_wipe_volatile(seed_bytes, sizeof(seed_bytes));
    js_vbc4_wipe_volatile(flags_bytes, sizeof(flags_bytes));
    js_vbc4_wipe_volatile(len_bytes, sizeof(len_bytes));
}

JS_LOCAL jbyteArray JNICALL
jsn_r21(JNIEnv *env, jclass cls, jbyteArray payload, jint seed, jint flags) {
    (void)cls;
    if (!payload) return NULL;
    jsize len = (*env)->GetArrayLength(env, payload);
    jbyte *bytes = len > 0 ? (*env)->GetByteArrayElements(env, payload, NULL) : NULL;
    if (len > 0 && !bytes) return NULL;
    jbyteArray result = (*env)->NewByteArray(env, len);
    if (!result) {
        if (bytes) (*env)->ReleaseByteArrayElements(env, payload, bytes, JNI_ABORT);
        return NULL;
    }
    unsigned char key[16], counter[16], stream[16];
    js_string_payload_material((int)seed, (int)flags, (int)len, key, counter);
    unsigned char *out = len > 0 ? (unsigned char*)malloc((size_t)len) : NULL;
    if (len > 0 && !out) {
        js_vbc4_wipe_volatile(key, sizeof(key));
        js_vbc4_wipe_volatile(counter, sizeof(counter));
        if (bytes) (*env)->ReleaseByteArrayElements(env, payload, bytes, JNI_ABORT);
        return NULL;
    }
    int offset = 0;
    while (offset < len) {
        js_aes128_encrypt_block(counter, key, stream);
        int chunk = len - offset < 16 ? len - offset : 16;
        for (int index = 0; index < chunk; index++) out[offset + index] = (unsigned char)(((unsigned char*)bytes)[offset + index] ^ stream[index]);
        offset += chunk;
        js_ctr_inc(counter);
    }
    if (len > 0) (*env)->SetByteArrayRegion(env, result, 0, len, (const jbyte*)out);
    if (out) { js_vbc4_wipe_volatile(out, (size_t)len); free(out); }
    if (bytes) (*env)->ReleaseByteArrayElements(env, payload, bytes, JNI_ABORT);
    js_vbc4_wipe_volatile(key, sizeof(key));
    js_vbc4_wipe_volatile(counter, sizeof(counter));
    js_vbc4_wipe_volatile(stream, sizeof(stream));
    return (*env)->ExceptionCheck(env) ? NULL : result;
}
/* Check if a function pointer starts with a hook/trampoline pattern.
 * Common hooking frameworks patch the first bytes of functions with:
 *   x86/x64: 0xE9 (JMP rel32), 0xFF 0x25 (JMP [rip+disp32])
 *   ARM/ARM64: branch instructions
 * Returns 1 if the pointer looks clean, 0 if trampoline detected. */
static int js_check_trampoline(const void *func_ptr) {
    if (!func_ptr) return 0;
    const unsigned char *p = (const unsigned char *)func_ptr;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    if (p[0] == 0xE9) return 0; /* JMP rel32 - classic inline hook */
    if (p[0] == 0xFF && p[1] == 0x25) return 0; /* JMP [rip+disp32] - PLT/GOT hook */
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return 0; /* mov rax,imm64; jmp rax */
    if (p[0] == 0xCC) return 0; /* INT3 software breakpoint planted at entry (debugger/hook) */
    if (p[0] == 0xEB) return 0; /* JMP rel8 - short inline hook trampoline */
    if (p[0] == 0x68 && p[5] == 0xC3) return 0; /* push imm32; ret - hook redirect */
    if (p[0] == 0xFF && p[1] == 0xE0) return 0; /* jmp rax - direct register redirect at entry */
#elif defined(__aarch64__) || defined(_M_ARM64)
    unsigned int insn = ((unsigned int)p[0]) | ((unsigned int)p[1] << 8) |
                        ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    if ((insn & 0xFC000000u) == 0x14000000u) return 0; /* B (unconditional) */
#elif defined(__arm__) || defined(_M_ARM)
    unsigned int insn = ((unsigned int)p[0]) | ((unsigned int)p[1] << 8) |
                        ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    if ((insn & 0x0E000000u) == 0x0A000000u) return 0; /* B/BL */
#endif
    return 1;
}

/* Detect Frida/Xposed/other instrumentation via /proc/self/maps (Linux/Android).
 * Returns 1 if suspicious libraries are found, 0 if clean. */
static int js_detect_instrumentation(void) {
#if defined(__linux__) || defined(__ANDROID__)
    FILE *maps = NULL;
    char line[512];
    maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "frida") || strstr(line, "xposed") ||
            strstr(line, "substrate") || strstr(line, "cydia") ||
            strstr(line, "libinject") || strstr(line, "re.frida.server")) {
            fclose(maps);
            return 1;
        }
    }
    fclose(maps);
    return 0;
#else
    return 0;
#endif
}

static uint32_t js_vm_entry_integrity_state(void) {
    uint32_t state = 0x4A56534Du;
    state ^= js_check_trampoline((const void*)jsn_r20) ? 0x13579BDFu : 0x2468ACE0u;
    state = (state << 5) | (state >> 27);
    state ^= js_check_trampoline((const void*)js_vm_execute_resource) ? 0x9E3779B9u : 0x7F4A7C15u;
    state = (state << 7) | (state >> 25);
    state ^= js_check_trampoline((const void*)js_vm_parse_program) ? 0x85EBCA77u : 0xC2B2AE35u;
    state = (state << 11) | (state >> 21);
    state ^= js_check_trampoline((const void*)js_vbc4_hmac_sha256_with_nonce) ? 0x27D4EB2Fu : 0x165667B1u;
    state = (state << 13) | (state >> 19);
    state ^= js_detect_instrumentation() ? 0xDEADBEEFu : 0xA5A5A5A5u;
    return state;
}

static void js_vm_write_entry_integrity_bytes(unsigned char out[4]) {
    js_write_be32_tmp(out, js_vm_entry_integrity_state());
}

/* Global trace poison seed: set by anti-trace detection to corrupt CP decryption.
 * Once non-zero, all subsequent CP decryptions produce garbage plaintext,
 * making trace dumps useless. Reset to 0 on each new program execution. */
static volatile int js_vm_hot_integrity_baseline_clean = 0;

static int js_vm_hot_integrity_clean(void) {
    return js_check_trampoline((const void*)js_vm_execute_resource) &&
           js_check_trampoline((const void*)js_vm_parse_program) &&
           js_check_trampoline((const void*)js_vbc4_hmac_sha256_with_nonce) &&
           js_check_trampoline((const void*)js_vm_execute) &&
           js_check_trampoline((const void*)js_vm_invoke_method) &&
           js_check_trampoline((const void*)js_vbc4_decrypt_block) &&
           !js_detect_instrumentation();
}

JS_HIDDEN volatile uint32_t js_vm_trace_poison_seed = 0;
static uint64_t js_vm_probe_monotonic_ticks(void) {
#if defined(_WIN32)
    LARGE_INTEGER counter;
    if (QueryPerformanceCounter(&counter)) return (uint64_t)counter.QuadPart;
    return (uint64_t)GetTickCount64();
#elif defined(CLOCK_MONOTONIC_RAW)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
    return (uint64_t)clock();
#else
    return (uint64_t)clock();
#endif
}

static uint64_t js_vm_probe_rdtsc(void) {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int cpu_info[4] = {0, 0, 0, 0};
    __cpuid(cpu_info, 0);
    return __rdtsc() ^ ((uint64_t)(uint32_t)cpu_info[1] << 32) ^ (uint32_t)cpu_info[3];
#elif (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    uint32_t lo = 0, hi = 0, eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64_t)hi << 32) | lo) ^ ((uint64_t)ebx << 32) ^ edx;
#else
    return 0;
#endif
}

static int js_vm_simulation_probe_score(int dispatch_step, uint32_t trace_state) {
    static uint64_t last_tick = 0;
    static uint64_t last_tsc = 0;
    static uint32_t repeat_pattern = 0;
    if (dispatch_step <= 0 || (dispatch_step & JS_VBC4_SIMULATION_PROBE_GATE) != 0) return 0;
    uint64_t tick_a = js_vm_probe_monotonic_ticks();
    uint64_t tsc_a = js_vm_probe_rdtsc();
    volatile uint32_t mix = (uint32_t)trace_state ^ (uint32_t)dispatch_step ^ JS_VBC4_DISPATCH_MIX_B;
    for (int i = 0; i < 32; i++) {
        mix ^= mix << 13;
        mix ^= mix >> 17;
        mix ^= mix << 5;
    }
    uint64_t tick_b = js_vm_probe_monotonic_ticks();
    uint64_t tsc_b = js_vm_probe_rdtsc();
    uint64_t tick_delta = tick_b >= tick_a ? tick_b - tick_a : tick_a - tick_b;
    uint64_t tsc_delta = (tsc_a && tsc_b && tsc_b >= tsc_a) ? (tsc_b - tsc_a) : 0;
    int score = 0;
    if (last_tick && tick_a == last_tick) score++;
    if (last_tsc && tsc_a && tsc_a == last_tsc) score++;
    if (tsc_a && tsc_b && tsc_b <= tsc_a) score += 2;
    if (tsc_delta && tick_delta == 0 && tsc_delta > 20000000ULL) score++;
    if (tick_delta > 0 && tsc_delta > 0) {
        uint64_t ratio = tsc_delta / tick_delta;
        if (ratio == 0 || ratio > 1000000000ULL) score++;
    }
    uint32_t pattern = (uint32_t)(tick_delta ^ (tsc_delta << 7) ^ (uint64_t)mix);
    if (pattern == repeat_pattern && pattern != 0) score++;
    repeat_pattern = pattern;
    last_tick = tick_a;
    last_tsc = tsc_a;
    return score;
}

/* ---- Strong-signal anti-debug: syscall/kernel-boundary checks ----
 *
 * Design notes / threat model:
 *  - Weak signals (IsDebuggerPresent, libc fopen("/proc/self/status")) are trivially
 *    defeated by hooking a single userland export. These functions instead read
 *    kernel-owned state through the raw syscall ABI (Linux) or direct PEB / NtQuery
 *    structures (Windows), which an attacker cannot spoof without a kernel-mode or
 *    full-emulation effort that is far costlier than an inline export hook.
 *  - All checks are conservative: a return of 1 means "high-confidence debugger".
 *    Ambiguous/unsupported results return 0 (fail-open for that probe) so legitimate
 *    sandboxes, containers, and locked-down environments without /proc do NOT get
 *    mis-flagged. The caller still requires a repeated streak before poisoning state,
 *    so a single false positive can never corrupt a legitimate long-running VM loop.
 */

/* Anti-trace trap: detect debugger/trace attachment during VM dispatch.
 * Returns 1 if suspicious activity detected (should poison dispatch), 0 if clean.
 * Uses platform-specific debugger checks and timing anomaly detection. */
static int js_vm_anti_trace_check(int dispatch_step, uint32_t *trace_state) {
    /* Gate: only check every 32nd dispatch to amortize cost */
    if (dispatch_step <= 0 || (dispatch_step & 31) != 0) return 0;

    int suspicious = 0;
    int strong_suspicious = 0;
    static int hot_integrity_streak = 0;
    static int simulation_score_streak = 0;

    /* High-confidence debugger detection at the syscall / kernel-structure boundary.
     * This replaces the easily-hooked IsDebuggerPresent / libc fopen("/proc") signals
     * with kernel-owned truth (raw ptrace/openat+read on Linux, PEB + NtQuery on
     * Windows, sysctl P_TRACED on macOS). A positive verdict is treated as strong. */
    {
        static int strong_debug_streak = 0;
        if (js_vm_strong_debugger_present()) {
            strong_debug_streak++;
            /* Require two consecutive confirmations to absorb any transient races
             * (e.g. a profiler briefly attaching) before poisoning dispatch state. */
            if (strong_debug_streak >= 2) { suspicious = 1; strong_suspicious = 1; }
        } else {
            strong_debug_streak = 0;
        }
    }

    /* Timing anomaly: measure wall-clock between checks. If delta is too large
     * (single-step breakpoint), flag as suspicious. Use clock() as a cheap proxy.
     * We encode the expected cadence into trace_state so it's build-specific. */
    {
        static clock_t last_check = 0;
        static int slow_check_streak = 0;
        clock_t now = clock();
        if (last_check != 0) {
            clock_t delta = now - last_check;
            /* Timing is a weak signal: normal execution can cross resource I/O,
             * class loading, or JIT safepoints. Require repeated large CPU-time
             * gaps before poisoning dispatch state. */
            if (delta > (CLOCKS_PER_SEC * 10)) {
                slow_check_streak++;
                if (slow_check_streak >= 5) slow_check_streak = 5;
            } else {
                slow_check_streak = 0;
            }
        }
        last_check = now;
    }

    /* Periodic inline-hook self-check on the hot decrypt+dispatch path. The entry
     * check in js_vm_execute_resource only runs once; an attacker can install a hook
     * AFTER entry to trace per-opcode behavior. Re-verifying here (every 32nd dispatch,
     * same amortized gate) means a mid-execution patch on any of these functions feeds
     * the same poison path. Arm it only when JNI_OnLoad observed a clean baseline;
     * selected toolchains legitimately start helpers through import thunks, and treating
     * that as a live hook corrupts normal long-running VM loops. */
    if (js_vm_hot_integrity_baseline_clean && !js_vm_hot_integrity_clean()) {
        hot_integrity_streak++;
        if (hot_integrity_streak >= 3) { suspicious = 1; strong_suspicious = 1; }
    } else {
        hot_integrity_streak = 0;
    }

    int simulation_score = js_vm_simulation_probe_score(dispatch_step, *trace_state);
    if (simulation_score >= 2) {
        simulation_score_streak += simulation_score;
        if (simulation_score_streak >= 16 && strong_suspicious) suspicious = 1;
    } else if (simulation_score_streak > 0) {
        simulation_score_streak--;
    }

    /* Integrate into trace_state: the state accumulates over the dispatch session
     * and is used to poison opcode matching when trace is detected. */
    if (suspicious) {
        if (!strong_suspicious) return 0;
        *trace_state ^= 0xDEAD1337u;
        *trace_state = (*trace_state << 7) | (*trace_state >> 25);
        *trace_state += (uint32_t)dispatch_step * 0x01000193u;
        /* Poison CP decryption: once set, all CP entries decrypt to garbage */
        js_vm_trace_poison_seed = *trace_state ^ 0xC0FFEE42u;
    }

    return suspicious;
}

/* Poison an opcode to produce a plausible but wrong dispatch target.
 * When anti-trace detects debugging, this corrupts the salt used for
 * opcode matching, causing the dispatch to land on a wrong handler. */
static uint32_t js_vm_poison_dispatch_salt(uint32_t salt, uint32_t trace_state) {
    if (trace_state == 0) return salt;
    return salt ^ (trace_state * 0x9E3779B9u);
}

/* ---- VM Call Gate: token->resource registry ---- */
/* Call-gate entries are keyed by build/method tokens. The VM never forms an
 * plaintext symbolic signature in native memory for dispatch lookup. */
static int js_jni_callgate(JNIEnv *env, jclass cls, jobject obj, jmethodID mid, const jvalue *args, int ret_type, jvalue *out, int strict_check) {
    if (strict_check) {
        /* Trampoline/patch detection: verify JNI function pointers are not hooked */
        if (!js_check_trampoline((const void*)mid)) return 0;
        if (env && (*env) && !js_check_trampoline((const void*)(*env)->FindClass)) return 0;
        if (env && (*env) && !js_check_trampoline((const void*)(*env)->CallObjectMethodA)) return 0;
        /* Frida/Xposed detection via /proc/self/maps */
        if (js_detect_instrumentation()) return 0;
    }
    return 1;
}

JS_HIDDEN int js_vm_parse_program(const unsigned char *data, int len, js_vm_program *p, const unsigned char *state_binding, int state_binding_len) {
    int pos = 0;
    int parse_stage = 0;
    unsigned int u = 0;
    uint32_t u4 = 0;
    int build_seed = 0;
    unsigned char vbc4_nonce[16];
    unsigned char vbc4_wrapped_seed[16];
    uint32_t vbc4_key_id = 0;
    int vbc4_flags = 0;
    int block_count = 0;
    int *block_ids = NULL;
    int *block_next_ids = NULL;
    int *block_parse_order = NULL;
    int *seen_block_ids = NULL;
    unsigned char **logical_blocks = NULL;
    uint32_t *logical_block_sizes = NULL;
    unsigned char *cp = NULL;
    unsigned char *insn = NULL;
    unsigned char *exc = NULL;
    unsigned char *block = NULL;

    if (!data || !p) return 0;
    memset(p, 0, sizeof(*p));
    p->max_stack = 8;
    p->max_locals = 8;
    p->metadata_cp_index = -1;
    p->method_local_profile = 0;
    p->vbc4_flags = 0;
    p->nested_vm_profile = 0;

#define JS_VM_PARSE_FAIL do { \
    js_vm_last_parse_stage = parse_stage; \
    if (cp) { js_vbc4_wipe_volatile(cp, (size_t)cp_enc_sz); free(cp); } \
    if (insn) { js_vbc4_wipe_volatile(insn, (size_t)insn_enc_sz); free(insn); } \
    if (exc) { js_vbc4_wipe_volatile(exc, (size_t)exc_enc_sz); free(exc); } \
    if (block) { js_vbc4_wipe_volatile(block, (size_t)block_enc_sz); free(block); } \
    if (logical_blocks) { for (int lbi = 0; lbi < block_count; lbi++) { if (logical_blocks[lbi]) { size_t lsz = logical_block_sizes ? (size_t)logical_block_sizes[lbi] : 0u; js_vbc4_wipe_volatile(logical_blocks[lbi], lsz); free(logical_blocks[lbi]); } } free(logical_blocks); } \
    free(logical_block_sizes); \
    free(seen_block_ids); \
    free(block_parse_order); \
    free(block_next_ids); \
    free(block_ids); \
    js_vm_free_program(NULL, p); \
    return 0; \
} while (0)

    uint32_t cp_plain_sz = 0, cp_enc_sz = 0;
    uint32_t cp_stored_sz = 0;
    uint32_t insn_plain_sz = 0, insn_enc_sz = 0;
    uint32_t insn_stored_sz = 0;
    uint32_t exc_plain_sz = 0, exc_enc_sz = 0;
    uint32_t exc_stored_sz = 0;
    uint32_t block_plain_sz = 0, block_enc_sz = 0;
    uint32_t block_stored_sz = 0;

    parse_stage = 1;
    memset(vbc4_nonce, 0, sizeof(vbc4_nonce));
    memset(vbc4_wrapped_seed, 0, sizeof(vbc4_wrapped_seed));
    if (len < 80) JS_VM_PARSE_FAIL;
    uint32_t magic = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    if (magic != 0x56424334u) JS_VM_PARSE_FAIL;

    pos = 4;
    if (!js_vm_read_u2(data, len, &pos, &u) || u != 4) JS_VM_PARSE_FAIL; /* version */
    if (pos + 16 > len) JS_VM_PARSE_FAIL;
    memcpy(vbc4_nonce, data + pos, sizeof(vbc4_nonce));
    pos += 16;
    if (!js_vm_read_u4(data, len, &pos, &u4)) JS_VM_PARSE_FAIL; /* keyId */
    vbc4_key_id = u4;
    if (pos + 16 > len) JS_VM_PARSE_FAIL;
    memcpy(vbc4_wrapped_seed, data + pos, sizeof(vbc4_wrapped_seed));
    pos += 16;
    if (!js_vm_read_u2(data, len, &pos, &u)) JS_VM_PARSE_FAIL; /* flags */
    vbc4_flags = (int)u;
    if (((unsigned int)vbc4_flags & JS_VBC4_REQUIRED_FLAGS) != JS_VBC4_REQUIRED_FLAGS) JS_VM_PARSE_FAIL; /* require full VBC4 max-strength feature set */
    p->vbc4_flags = (uint32_t)vbc4_flags;
    parse_stage = 2;
    parse_stage = 21;
    if (!js_vbc4_unwrap_seed(vbc4_nonce, vbc4_wrapped_seed, state_binding, state_binding_len, &build_seed)) JS_VM_PARSE_FAIL;
    parse_stage = 22;
    if (js_vbc4_key_id(build_seed, vbc4_nonce) != vbc4_key_id) JS_VM_PARSE_FAIL;
    memcpy(p->nonce, vbc4_nonce, sizeof(p->nonce));
    js_vm_init_resident_key_mask(p, vbc4_nonce);
    js_vm_store_resident_build_seed(p, build_seed);
    if (!js_vm_read_u2(data, len, &pos, &u)) JS_VM_PARSE_FAIL; /* block_count */
    block_count = (int)u;
    if (block_count <= 0) JS_VM_PARSE_FAIL;

    parse_stage = 3;
if (!js_vm_read_u4(data, len, &pos, &cp_plain_sz)) JS_VM_PARSE_FAIL; /* cp_plain_size */
if (!js_vm_read_u4(data, len, &pos, &cp_enc_sz)) JS_VM_PARSE_FAIL; /* cp_encrypted_size */
if (cp_plain_sz == 0 || cp_enc_sz == 0 || cp_enc_sz > (uint32_t)(len - pos)) JS_VM_PARSE_FAIL; /* cp_plain_sz is the aggregate plaintext size; cp_enc_sz is the per-entry CP section container length and may legitimately differ */
    cp = (unsigned char*)malloc((size_t)cp_enc_sz);
    if (!cp) JS_VM_PARSE_FAIL;
    memcpy(cp, data + pos, (size_t)cp_enc_sz);
    pos += (int)cp_enc_sz;
    /* Early MAC verification gates decryption before parsing plaintext sections. */
    {
        unsigned char early_mac[32];
if (len < 33 || data[len - 1] != 32) JS_VM_PARSE_FAIL;
        js_vbc4_hmac_sha256_with_nonce(data, len - 33, build_seed, vbc4_nonce, early_mac);
        if (memcmp(data + len - 33, early_mac, 32) != 0) {
            js_vbc4_wipe_volatile(early_mac, sizeof(early_mac));
            JS_VM_PARSE_FAIL;
        }
        int mac_key = (int)(((uint32_t)early_mac[0] << 24) | ((uint32_t)early_mac[1] << 16) |
                      ((uint32_t)early_mac[2] << 8) | (uint32_t)early_mac[3]);
        js_vm_store_resident_mac_key(p, mac_key ^ build_seed);
        js_vbc4_wipe_volatile(early_mac, sizeof(early_mac));
    }

    /* Versioned CP section encryption: decrypt the index once, keep entries encrypted and decode on first use. */
    parse_stage = 4;
    js_vbc4_decrypt_block(cp, (int)cp_enc_sz, build_seed, vbc4_nonce, 1, 0);
    int raw_pos = 0;
if (!js_vm_read_u2(cp, (int)cp_enc_sz, &raw_pos, &u) || u != JS_VBC4_CP_SECTION_VERSION) JS_VM_PARSE_FAIL;
    if (!js_vm_read_u2(cp, (int)cp_enc_sz, &raw_pos, &u)) JS_VM_PARSE_FAIL;
    p->cp_count = (int)u;
    if (p->cp_count > 0) {
        p->cp = (js_vm_cp*)calloc((size_t)p->cp_count, sizeof(js_vm_cp));
        if (!p->cp) JS_VM_PARSE_FAIL;
    }
    for (int ci = 0; ci < p->cp_count; ci++) {
        unsigned int entry_plain_sz = 0, entry_enc_sz = 0;
        unsigned int entry_stored_sz = 0;
if (!js_vm_read_u4(cp, (int)cp_enc_sz, &raw_pos, &entry_plain_sz)) JS_VM_PARSE_FAIL;
if (!js_vm_read_u4(cp, (int)cp_enc_sz, &raw_pos, &entry_stored_sz)) JS_VM_PARSE_FAIL;
if (!js_vm_read_u4(cp, (int)cp_enc_sz, &raw_pos, &entry_enc_sz)) JS_VM_PARSE_FAIL;
        unsigned int entry_stored_zstd = (entry_stored_sz & 0x80000000u) != 0;
        entry_stored_sz &= 0x7FFFFFFFu;
if (entry_plain_sz == 0 || entry_stored_sz == 0 || entry_stored_sz > entry_enc_sz || entry_enc_sz > (unsigned int)((int)cp_enc_sz - raw_pos)) JS_VM_PARSE_FAIL;
if (!entry_stored_zstd && entry_stored_sz != entry_plain_sz) JS_VM_PARSE_FAIL;
if (entry_stored_zstd && entry_stored_sz >= entry_plain_sz) JS_VM_PARSE_FAIL;
        p->cp[ci].enc = (unsigned char*)malloc((size_t)entry_enc_sz);
        if (!p->cp[ci].enc) JS_VM_PARSE_FAIL;
        memcpy(p->cp[ci].enc, cp + raw_pos, (size_t)entry_enc_sz);
        p->cp[ci].enc_len = (int)entry_enc_sz;
        p->cp[ci].plain_len = (int)entry_plain_sz;
        p->cp[ci].stored_len = (int)entry_stored_sz;
        p->cp[ci].entry_id = ci;
        p->cp[ci].stored_zstd = entry_stored_zstd ? 1u : 0u;
        js_vbc4_aes_material(build_seed, vbc4_nonce, JS_VBC4_SECTION_CONSTANT_POOL_ENTRY, ci, p->cp[ci].key, p->cp[ci].iv);
        raw_pos += (int)entry_enc_sz;
    }
if (raw_pos != (int)cp_enc_sz) JS_VM_PARSE_FAIL;
    js_vbc4_wipe_volatile(cp, (size_t)cp_enc_sz);
    free(cp);
    cp = NULL;

    block_ids = (int*)calloc((size_t)block_count, sizeof(int));
    block_next_ids = (int*)calloc((size_t)block_count, sizeof(int));
    block_parse_order = (int*)calloc((size_t)block_count, sizeof(int));
    if (!block_ids || !block_next_ids || !block_parse_order) JS_VM_PARSE_FAIL;
    for (int bi = 0; bi < block_count; bi++) {
        if (!js_vm_read_u2(data, len, &pos, &u)) JS_VM_PARSE_FAIL; /* blockId */
        block_ids[bi] = (int)u;
        if (!js_vm_read_u4(data, len, &pos, &u4)) JS_VM_PARSE_FAIL; /* entryToken */
        if (!js_vm_read_u4(data, len, &pos, &u4)) JS_VM_PARSE_FAIL; /* masked next block dispatch edge */
        block_next_ids[bi] = js_vbc4_decode_block_dispatch_next(build_seed, block_ids[bi], block_count, u4);
    }

    parse_stage = 5;
    if (vbc4_flags & 0x0010) {
        logical_blocks = (unsigned char**)calloc((size_t)block_count, sizeof(unsigned char*));
        logical_block_sizes = (uint32_t*)calloc((size_t)block_count, sizeof(uint32_t));
        seen_block_ids = (int*)calloc((size_t)block_count, sizeof(int));
        if (!logical_blocks || !logical_block_sizes || !seen_block_ids) JS_VM_PARSE_FAIL;

        for (int storage_bi = 0; storage_bi < block_count; storage_bi++) {
            int logical_id = block_ids[storage_bi];
            if (logical_id < 0 || logical_id >= block_count || seen_block_ids[logical_id]) JS_VM_PARSE_FAIL;
            seen_block_ids[logical_id] = 1;
            if (block_next_ids[storage_bi] < 0 || block_next_ids[storage_bi] > block_count) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u4(data, len, &pos, &block_plain_sz)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u4(data, len, &pos, &block_stored_sz)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u4(data, len, &pos, &block_enc_sz)) JS_VM_PARSE_FAIL;
            if (block_plain_sz == 0 || block_stored_sz == 0 || block_stored_sz > block_enc_sz || block_enc_sz > (uint32_t)(len - pos)) JS_VM_PARSE_FAIL;
            if (block_stored_sz != block_plain_sz && block_stored_sz >= block_plain_sz) JS_VM_PARSE_FAIL;
            block = (unsigned char*)malloc((size_t)block_enc_sz);
            if (!block) JS_VM_PARSE_FAIL;
            memcpy(block, data + pos, (size_t)block_enc_sz);
            pos += (int)block_enc_sz;
            js_vbc4_decrypt_block(block, (int)block_enc_sz, build_seed, vbc4_nonce, 2, logical_id);
            unsigned char *block_plain = js_vbc4_zstd_decompress_owned(block, block_stored_sz, block_plain_sz);
            js_vbc4_wipe_volatile(block, (size_t)block_enc_sz);
            free(block);
            block = NULL;
            block_enc_sz = 0;
            if (!block_plain) JS_VM_PARSE_FAIL;
            if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0) {
                unsigned char *nested_plain = NULL;
                uint32_t nested_plain_sz = 0;
                uint32_t nested_profile = 0;
                if (!js_vm_decode_nested_register_block(block_plain, (int)block_plain_sz, (uint32_t)build_seed, logical_id, &nested_plain, &nested_plain_sz, &nested_profile)) {
                    js_vbc4_wipe_volatile(block_plain, (size_t)block_plain_sz);
                    free(block_plain);
                    JS_VM_PARSE_FAIL;
                }
                js_vbc4_wipe_volatile(block_plain, (size_t)block_plain_sz);
                free(block_plain);
                block_plain = nested_plain;
                block_plain_sz = nested_plain_sz;
                if (p->nested_vm_profile == 0u) p->nested_vm_profile = nested_profile;
                else if (p->nested_vm_profile != nested_profile) JS_VM_PARSE_FAIL;
            }
            logical_blocks[logical_id] = block_plain;
            logical_block_sizes[logical_id] = block_plain_sz;
        }
        for (int bi = 0; bi < block_count; bi++) {
            if (!seen_block_ids[bi] || !logical_blocks[bi] || logical_block_sizes[bi] == 0) JS_VM_PARSE_FAIL;
        }

        memset(seen_block_ids, 0, (size_t)block_count * sizeof(int));
        int cursor_block = 0;
        for (int dispatch_index = 0; dispatch_index < block_count; dispatch_index++) {
            if (cursor_block < 0 || cursor_block >= block_count || seen_block_ids[cursor_block]) JS_VM_PARSE_FAIL;
            seen_block_ids[cursor_block] = 1;
            block_parse_order[dispatch_index] = cursor_block;
            int next_block = -1;
            for (int storage_bi = 0; storage_bi < block_count; storage_bi++) {
                if (block_ids[storage_bi] == cursor_block) { next_block = block_next_ids[storage_bi]; break; }
            }
            if (dispatch_index + 1 < block_count) {
                if (next_block < 0 || next_block >= block_count) JS_VM_PARSE_FAIL;
            } else if (next_block != block_count) {
                JS_VM_PARSE_FAIL;
            }
            cursor_block = next_block;
        }

        int logical_insn_index = 0;
        for (int dispatch_index = 0; dispatch_index < block_count; dispatch_index++) {
            int bi = block_parse_order[dispatch_index];
            block = logical_blocks[bi];
            block_plain_sz = logical_block_sizes[bi];
            block_enc_sz = block_plain_sz;
            logical_blocks[bi] = NULL;
            logical_block_sizes[bi] = 0;
            if (!block) JS_VM_PARSE_FAIL;
            int block_pos = 0;
            unsigned int register_count = 0, register_insn_count = 0, stack_insn_count = 0;
            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &register_count)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &register_insn_count)) JS_VM_PARSE_FAIL;
            p->reg_program.register_count = (int)register_count;
            int base_insn = p->insn_count;
            for (unsigned int ri = 0; ri < register_insn_count; ri++) {
                unsigned int raw_opcode = 0, flags = 0, op_count = 0, srcA = 0, srcB = 0;
                if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &raw_opcode)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &flags)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &op_count)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &srcA)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &srcB)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u4(block, (int)block_plain_sz, &block_pos, &u4)) JS_VM_PARSE_FAIL;
                if ((flags & 0x8000u) != 0) continue;
                if ((flags & 0x0001u) == 0) continue;
                int opcode_mask_index = logical_insn_index++;
                jint raw_decoded_opcode = (jint)(raw_opcode ^ (unsigned int)js_vbc4_opcode_unmask(build_seed, opcode_mask_index));
                jint decoded_opcode = (raw_decoded_opcode >= JS_VM_SUPER_BASE && raw_decoded_opcode <= JS_VM_SUPER_INVOKE) ? raw_decoded_opcode : js_vm_canonical_opcode(raw_decoded_opcode);
                jint opcode = decoded_opcode;
                jint original_opcode = ((flags & 0x0002u) != 0 && srcB != 0) ? js_vm_canonical_opcode((jint)srcB) : opcode;
                if (!js_vm_reg_program_append(p, decoded_opcode, (jint)flags, (jint)op_count, (jint)srcA, (jint)srcB, (jint)u4, opcode, original_opcode)) JS_VM_PARSE_FAIL;
                if (opcode == JS_VM_REG_META) { p->metadata_cp_index = (int)u4; continue; }
                if ((flags & 0x0002u) != 0 && srcB != 0) opcode = original_opcode;
                if ((flags & 0x0004u) != 0) {
                    if (!js_vm_append_folded_super_insn(p, (jint)srcA, (jint)srcB, (jint)u4)) JS_VM_PARSE_FAIL;
                    logical_insn_index++;
                    continue;
                }
                js_vm_insn *grown = (js_vm_insn*)realloc(p->insns, (size_t)(p->insn_count + 1) * sizeof(js_vm_insn));
                if (!grown) JS_VM_PARSE_FAIL;
                p->insns = grown;
                memset(&p->insns[p->insn_count], 0, sizeof(js_vm_insn));
                p->insns[p->insn_count].opcode = js_vm_store_resident_opcode(p, p->insn_count, opcode);
                p->insns[p->insn_count].op_count = (jint)op_count;
                if (op_count > 0) {
                    p->insns[p->insn_count].ops = (jint*)calloc((size_t)op_count, sizeof(jint));
                    if (!p->insns[p->insn_count].ops) JS_VM_PARSE_FAIL;
                    p->insns[p->insn_count].ops[0] = js_vm_store_resident_operand(p, p->insn_count, 0, (jint)u4);
                    for (unsigned int extra = 1; extra < op_count; extra++) {
                        unsigned int cont_opcode = 0, cont_flags = 0, cont_dst = 0, cont_srcA = 0, cont_srcB = 0, cont_operand = 0;
                        if (++ri >= register_insn_count) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_opcode)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_flags)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_dst)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_srcA)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_srcB)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u4(block, (int)block_plain_sz, &block_pos, &cont_operand)) JS_VM_PARSE_FAIL;
                        if ((cont_flags & 0x8000u) == 0 || cont_opcode != JS_VM_REG_OPERAND_CONT) JS_VM_PARSE_FAIL;
                        if (!js_vm_reg_program_append(p, (jint)cont_opcode, (jint)cont_flags, (jint)cont_dst, (jint)cont_srcA, (jint)cont_srcB, (jint)cont_operand, (jint)cont_opcode, (jint)cont_opcode)) JS_VM_PARSE_FAIL;
                        p->insns[p->insn_count].ops[extra] = js_vm_store_resident_operand(p, p->insn_count, (int)extra, (jint)cont_operand);
                    }
                }
                if (js_vm_load_resident_opcode(p, p->insn_count) == JS_VM_MAXS && p->insns[p->insn_count].op_count >= 2) {
                    jint decoded_max_stack = js_vm_load_resident_operand(p, p->insn_count, 0);
                    jint decoded_max_locals = js_vm_load_resident_operand(p, p->insn_count, 1);
                    p->max_stack = decoded_max_stack > 0 ? decoded_max_stack : 1;
                    p->max_locals = decoded_max_locals > 0 ? decoded_max_locals : 1;
                }
                p->insn_count++;
            }
            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &stack_insn_count)) JS_VM_PARSE_FAIL;
            if (stack_insn_count != 0) JS_VM_PARSE_FAIL;
            if (p->insn_count == base_insn && bi == 0) JS_VM_PARSE_FAIL;
            js_vbc4_wipe_volatile(block, (size_t)block_enc_sz);
            free(block);
            block = NULL;
            block_enc_sz = 0;
        }
        free(logical_blocks);
        logical_blocks = NULL;
        free(logical_block_sizes);
        logical_block_sizes = NULL;
        free(seen_block_ids);
        seen_block_ids = NULL;
        if (p->insn_count <= 0 || !p->insns || p->reg_program.insn_count <= 0 || !p->reg_program.insns) JS_VM_PARSE_FAIL;
    } else {
        if (!js_vm_read_u4(data, len, &pos, &insn_plain_sz)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u4(data, len, &pos, &insn_stored_sz)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u4(data, len, &pos, &insn_enc_sz)) JS_VM_PARSE_FAIL;
        if (insn_plain_sz == 0 || insn_stored_sz == 0 || insn_stored_sz > insn_enc_sz || insn_enc_sz > (uint32_t)(len - pos)) JS_VM_PARSE_FAIL;
        if (insn_stored_sz != insn_plain_sz && insn_stored_sz >= insn_plain_sz) JS_VM_PARSE_FAIL;
        insn = (unsigned char*)malloc((size_t)insn_enc_sz);
        if (!insn) JS_VM_PARSE_FAIL;
        memcpy(insn, data + pos, (size_t)insn_enc_sz);
        pos += (int)insn_enc_sz;
        js_vbc4_decrypt_block(insn, (int)insn_enc_sz, build_seed, vbc4_nonce, 2, block_ids[0]);
        unsigned char *insn_plain = js_vbc4_zstd_decompress_owned(insn, insn_stored_sz, insn_plain_sz);
        js_vbc4_wipe_volatile(insn, (size_t)insn_enc_sz);
        free(insn);
        insn = insn_plain;
        insn_enc_sz = insn_plain_sz;
        if (!insn) JS_VM_PARSE_FAIL;
        if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0) {
            unsigned char *nested_plain = NULL;
            uint32_t nested_plain_sz = 0;
            uint32_t nested_profile = 0;
            if (!js_vm_decode_nested_register_block(insn, (int)insn_plain_sz, (uint32_t)build_seed, block_ids[0], &nested_plain, &nested_plain_sz, &nested_profile)) JS_VM_PARSE_FAIL;
            js_vbc4_wipe_volatile(insn, (size_t)insn_enc_sz);
            free(insn);
            insn = nested_plain;
            insn_plain_sz = nested_plain_sz;
            insn_enc_sz = nested_plain_sz;
            p->nested_vm_profile = nested_profile;
        }

        int insn_pos = 0;
        unsigned int register_count = 0, register_insn_count = 0;
        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &register_count)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &register_insn_count)) JS_VM_PARSE_FAIL;
        p->reg_program.register_count = (int)register_count;
        int logical_insn_index = 0;
        for (unsigned int ri = 0; ri < register_insn_count; ri++) {
            unsigned int raw_opcode = 0, flags = 0, op_count = 0, srcA = 0, srcB = 0;
            if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &raw_opcode)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &flags)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &op_count)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &srcA)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &srcB)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u4(insn, (int)insn_plain_sz, &insn_pos, &u4)) JS_VM_PARSE_FAIL;
            if ((flags & 0x8000u) != 0) continue;
            if ((flags & 0x0001u) == 0) continue;
            int opcode_mask_index = logical_insn_index++;
            jint raw_decoded_opcode = (jint)(raw_opcode ^ (unsigned int)js_vbc4_opcode_unmask(build_seed, opcode_mask_index));
            jint decoded_opcode = (raw_decoded_opcode >= JS_VM_SUPER_BASE && raw_decoded_opcode <= JS_VM_SUPER_INVOKE) ? raw_decoded_opcode : js_vm_canonical_opcode(raw_decoded_opcode);
            jint opcode = decoded_opcode;
            jint original_opcode = ((flags & 0x0002u) != 0 && srcB != 0) ? js_vm_canonical_opcode((jint)srcB) : opcode;
            if (!js_vm_reg_program_append(p, decoded_opcode, (jint)flags, (jint)op_count, (jint)srcA, (jint)srcB, (jint)u4, opcode, original_opcode)) JS_VM_PARSE_FAIL;
            if (opcode == JS_VM_REG_META) { p->metadata_cp_index = (int)u4; continue; }
            if ((flags & 0x0002u) != 0 && srcB != 0) opcode = original_opcode;
            if ((flags & 0x0004u) != 0) {
                if (!js_vm_append_folded_super_insn(p, (jint)srcA, (jint)srcB, (jint)u4)) JS_VM_PARSE_FAIL;
                logical_insn_index++;
                continue;
            }
            js_vm_insn *grown = (js_vm_insn*)realloc(p->insns, (size_t)(p->insn_count + 1) * sizeof(js_vm_insn));
            if (!grown) JS_VM_PARSE_FAIL;
            p->insns = grown;
            memset(&p->insns[p->insn_count], 0, sizeof(js_vm_insn));
            p->insns[p->insn_count].opcode = js_vm_store_resident_opcode(p, p->insn_count, opcode);
            p->insns[p->insn_count].op_count = (jint)op_count;
            if (op_count > 0) {
                p->insns[p->insn_count].ops = (jint*)calloc((size_t)op_count, sizeof(jint));
                if (!p->insns[p->insn_count].ops) JS_VM_PARSE_FAIL;
                p->insns[p->insn_count].ops[0] = js_vm_store_resident_operand(p, p->insn_count, 0, (jint)u4);
                for (unsigned int extra = 1; extra < op_count; extra++) {
                    unsigned int cont_opcode = 0, cont_flags = 0, cont_dst = 0, cont_srcA = 0, cont_srcB = 0, cont_operand = 0;
                    if (++ri >= register_insn_count) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_opcode)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_flags)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_dst)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_srcA)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_srcB)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u4(insn, (int)insn_plain_sz, &insn_pos, &cont_operand)) JS_VM_PARSE_FAIL;
                    if ((cont_flags & 0x8000u) == 0 || cont_opcode != JS_VM_REG_OPERAND_CONT) JS_VM_PARSE_FAIL;
                    if (!js_vm_reg_program_append(p, (jint)cont_opcode, (jint)cont_flags, (jint)cont_dst, (jint)cont_srcA, (jint)cont_srcB, (jint)cont_operand, (jint)cont_opcode, (jint)cont_opcode)) JS_VM_PARSE_FAIL;
                    p->insns[p->insn_count].ops[extra] = js_vm_store_resident_operand(p, p->insn_count, (int)extra, (jint)cont_operand);
                }
            }
            if (js_vm_load_resident_opcode(p, p->insn_count) == JS_VM_MAXS && p->insns[p->insn_count].op_count >= 2) {
                jint decoded_max_stack = js_vm_load_resident_operand(p, p->insn_count, 0);
                jint decoded_max_locals = js_vm_load_resident_operand(p, p->insn_count, 1);
                p->max_stack = decoded_max_stack > 0 ? decoded_max_stack : 1;
                p->max_locals = decoded_max_locals > 0 ? decoded_max_locals : 1;
            }
            p->insn_count++;
        }
        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &u)) JS_VM_PARSE_FAIL;
        if (u != 0) JS_VM_PARSE_FAIL;
        if (p->insn_count <= 0 || !p->insns || p->reg_program.insn_count <= 0 || !p->reg_program.insns) JS_VM_PARSE_FAIL;
        js_vbc4_wipe_volatile(insn, (size_t)insn_enc_sz);
        free(insn);
        insn = NULL;
    }

    parse_stage = 6;
    if (!js_vm_read_u4(data, len, &pos, &exc_plain_sz)) JS_VM_PARSE_FAIL;
    if (!js_vm_read_u4(data, len, &pos, &exc_stored_sz)) JS_VM_PARSE_FAIL;
    if (!js_vm_read_u4(data, len, &pos, &exc_enc_sz)) JS_VM_PARSE_FAIL;
    if (exc_plain_sz == 0 || exc_stored_sz == 0 || exc_stored_sz > exc_enc_sz || exc_enc_sz > (uint32_t)(len - pos)) JS_VM_PARSE_FAIL;
    if (exc_stored_sz != exc_plain_sz && exc_stored_sz >= exc_plain_sz) JS_VM_PARSE_FAIL;
    exc = (unsigned char*)malloc((size_t)exc_enc_sz);
    if (!exc) JS_VM_PARSE_FAIL;
    memcpy(exc, data + pos, (size_t)exc_enc_sz);
    pos += (int)exc_enc_sz;
    js_vbc4_decrypt_block(exc, (int)exc_enc_sz, build_seed, vbc4_nonce, 3, 0);
    unsigned char *exc_plain = js_vbc4_zstd_decompress_owned(exc, exc_stored_sz, exc_plain_sz);
    js_vbc4_wipe_volatile(exc, (size_t)exc_enc_sz);
    free(exc);
    exc = exc_plain;
    exc_enc_sz = exc_plain_sz;
    if (!exc) JS_VM_PARSE_FAIL;

    int exc_pos = 0;
    if (!js_vm_read_u2(exc, (int)exc_plain_sz, &exc_pos, &u)) JS_VM_PARSE_FAIL;
    p->exception_count = (int)u;
    if (p->exception_count > 0) {
        p->exceptions = (js_vm_exception*)calloc((size_t)p->exception_count, sizeof(js_vm_exception));
        if (!p->exceptions) JS_VM_PARSE_FAIL;
    }
    for (int i = 0; i < p->exception_count; i++) {
        unsigned int encoded_token = 0, start = 0, end = 0, handler = 0, type_cp = 0;
        uint32_t expected_token = js_vbc4_exception_token(build_seed, i);
        if (!js_vm_read_u4(exc, (int)exc_plain_sz, &exc_pos, &encoded_token)) JS_VM_PARSE_FAIL;
        if ((uint32_t)encoded_token != expected_token) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u2(exc, (int)exc_plain_sz, &exc_pos, &start)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u2(exc, (int)exc_plain_sz, &exc_pos, &end)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u2(exc, (int)exc_plain_sz, &exc_pos, &handler)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u2(exc, (int)exc_plain_sz, &exc_pos, &type_cp)) JS_VM_PARSE_FAIL;
        start ^= js_vbc4_exception_mask(build_seed, i, 0, expected_token);
        end ^= js_vbc4_exception_mask(build_seed, i, 1, expected_token);
        handler ^= js_vbc4_exception_mask(build_seed, i, 2, expected_token);
        type_cp ^= js_vbc4_exception_mask(build_seed, i, 3, expected_token);
        p->exceptions[i].start = js_vm_store_resident_exception_field(p, i, 0, (jint)start);
        p->exceptions[i].end = js_vm_store_resident_exception_field(p, i, 1, (jint)end);
        p->exceptions[i].handler = js_vm_store_resident_exception_field(p, i, 2, (jint)handler);
        p->exceptions[i].type_cp = js_vm_store_resident_exception_field(p, i, 3, (jint)type_cp);
    }
    js_vbc4_wipe_volatile(exc, (size_t)exc_enc_sz);
    free(exc);
    exc = NULL;

    /* Authenticated size-jitter padding (VBC4_FLAG_PADDED = 0x0080): a u4 length
     * followed by that many MAC-covered random bytes. The padding carries no program
     * data; the parser only needs to skip it so the MAC trailer is located correctly.
     * It exists purely to break resource-size fingerprint clustering across methods. */
    if ((vbc4_flags & 0x0080) != 0) {
        parse_stage = 7;
        uint32_t pad_len = 0;
        if (!js_vm_read_u4(data, len, &pos, &pad_len)) JS_VM_PARSE_FAIL;
        if (pad_len > (uint32_t)(len - pos)) JS_VM_PARSE_FAIL;
        pos += (int)pad_len;
    }

    if ((vbc4_flags & 0x0004) != 0) {
        parse_stage = 8;
        unsigned char expected_mac[32];
        if (len - pos != 33) JS_VM_PARSE_FAIL;
        if (data[len - 1] != 32) JS_VM_PARSE_FAIL;
        js_vbc4_hmac_sha256_with_nonce(data, len - 33, build_seed, vbc4_nonce, expected_mac);
        if (memcmp(data + pos, expected_mac, 32) != 0) JS_VM_PARSE_FAIL;
        /* Preserve the verified MAC-derived key for downstream state binding. */
        int mac_key = (int)(((uint32_t)expected_mac[0] << 24) | ((uint32_t)expected_mac[1] << 16) |
                      ((uint32_t)expected_mac[2] << 8) | (uint32_t)expected_mac[3]);
        js_vm_store_resident_mac_key(p, mac_key ^ build_seed);
        js_vbc4_wipe_volatile(expected_mac, sizeof(expected_mac));
    }

    free(block_ids);
    free(block_next_ids);
    free(block_parse_order);
    js_vm_last_parse_stage = 0;
#undef JS_VM_PARSE_FAIL
    return 1;
}

static int js_vm_guest_frame_push(const js_vm_program *p) {
    int max_count = (int)(sizeof(js_vm_guest_frames) / sizeof(js_vm_guest_frames[0]));
    if (js_vm_guest_frame_count < 0 || js_vm_guest_frame_count > max_count) js_vm_guest_frame_count = 0;
    if (!p || !p->original_owner || !p->original_name || !p->original_desc) return 0;
    if (js_vm_guest_frame_count >= max_count) return 0;
    js_vm_guest_frames[js_vm_guest_frame_count].owner = p->original_owner;
    js_vm_guest_frames[js_vm_guest_frame_count].name = p->original_name;
    js_vm_guest_frames[js_vm_guest_frame_count].desc = p->original_desc;
    js_vm_guest_frame_count++;
    return 1;
}
static void js_vm_guest_frame_restore(int saved_count, int pushed) {
    int max_count = (int)(sizeof(js_vm_guest_frames) / sizeof(js_vm_guest_frames[0]));
    if (saved_count < 0) saved_count = 0;
    if (saved_count > max_count) saved_count = max_count;
    if (pushed) {
        for (int i = saved_count; i < js_vm_guest_frame_count && i < max_count; i++) {
            js_vm_guest_frames[i].owner = NULL;
            js_vm_guest_frames[i].name = NULL;
            js_vm_guest_frames[i].desc = NULL;
        }
    }
    js_vm_guest_frame_count = saved_count;
}
static void js_vm_apply_guest_stack_trace(JNIEnv *env, jobject throwable) {
    int max_count = (int)(sizeof(js_vm_guest_frames) / sizeof(js_vm_guest_frames[0]));
    if (js_vm_guest_frame_count < 0 || js_vm_guest_frame_count > max_count) js_vm_guest_frame_count = 0;
    if (!env || !throwable || !js_jni_cache.initialized || js_vm_guest_frame_count <= 0) return;
    if (!js_jni_cache.stack_trace_element_class || !js_jni_cache.stack_trace_element_init || !js_jni_cache.throwable_set_stack_trace) return;
    int snapshot_count = js_vm_guest_frame_count;
    if (snapshot_count < 0) snapshot_count = 0;
    if (snapshot_count > max_count) snapshot_count = max_count;
    if (snapshot_count <= 0) return;
    int count = snapshot_count < 64 ? snapshot_count : 64;
    jobjectArray frames = (*env)->NewObjectArray(env, count, js_jni_cache.stack_trace_element_class, NULL);
    if ((*env)->ExceptionCheck(env) || !frames) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return; }
    for (int i = 0; i < count; i++) {
        int frame_index = snapshot_count - 1 - i;
        if (frame_index < 0 || frame_index >= 64) break;
        const js_vm_guest_frame *frame = &js_vm_guest_frames[frame_index];
        char class_name[512];
        const char *owner = frame->owner ? frame->owner : "";
        size_t len = strlen(owner);
        if (len >= sizeof(class_name)) len = sizeof(class_name) - 1;
        memcpy(class_name, owner, len);
        class_name[len] = 0;
        for (size_t j = 0; j < len; j++) if (class_name[j] == '/') class_name[j] = '.';
        jstring cls = (*env)->NewStringUTF(env, class_name);
        jstring name = (*env)->NewStringUTF(env, frame->name ? frame->name : "");
        jstring file = (*env)->NewStringUTF(env, "VBC4.java");
        if ((*env)->ExceptionCheck(env) || !cls || !name || !file) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return; }
        jobject element = (*env)->NewObject(env, js_jni_cache.stack_trace_element_class, js_jni_cache.stack_trace_element_init, cls, name, file, (jint)-1);
        if ((*env)->ExceptionCheck(env) || !element) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return; }
        (*env)->SetObjectArrayElement(env, frames, i, element);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return; }
    }
    (*env)->CallVoidMethod(env, throwable, js_jni_cache.throwable_set_stack_trace, frames);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}
static jobject js_vm_call_value_of(JNIEnv *env, jmethodID mid, jvalue arg) {
    if (!js_jni_cache.initialized || !js_jni_cache.string_class || !mid) return NULL;
    return (*env)->CallStaticObjectMethodA(env, js_jni_cache.string_class, mid, &arg);
}

static char js_vm_return_descriptor(JNIEnv *env, jstring descriptor) {
    char ret = 'V';
    const char *desc = j2c(env, descriptor);
    if (desc) {
        const char *p = strchr(desc, ')');
        if (p && p[1]) ret = p[1];
    }
    rls(env, descriptor, desc);
    return ret;
}


static jobject js_vm_box_return(JNIEnv *env, char ret, js_vm_value v) {
    jvalue arg;
    jint i = 0;
    jlong l = 0;
    jfloat f = 0.0f;
    jdouble d = 0.0;
    memset(&arg, 0, sizeof(arg));
    switch (ret) {
        case 'V': return NULL;
        case 'Z': if (!js_vm_to_int(v, &i)) return NULL; arg.z = (i != 0); return js_vm_box_jvalue_arg(env, 'Z', arg);
        case 'B': if (!js_vm_to_int(v, &i)) return NULL; arg.b = (jbyte)i; return js_vm_box_jvalue_arg(env, 'B', arg);
        case 'S': if (!js_vm_to_int(v, &i)) return NULL; arg.s = (jshort)i; return js_vm_box_jvalue_arg(env, 'S', arg);
        case 'C': if (!js_vm_to_int(v, &i)) return NULL; arg.c = (jchar)i; return js_vm_box_jvalue_arg(env, 'C', arg);
        case 'I': if (!js_vm_to_int(v, &i)) return NULL; arg.i = i; return js_vm_box_jvalue_arg(env, 'I', arg);
        case 'J': if (!js_vm_to_long(v, &l)) return NULL; arg.j = l; return js_vm_box_jvalue_arg(env, 'J', arg);
        case 'F': if (!js_vm_to_float(v, &f)) return NULL; arg.f = f; return js_vm_box_jvalue_arg(env, 'F', arg);
        case 'D': if (!js_vm_to_double(v, &d)) return NULL; arg.d = d; return js_vm_box_jvalue_arg(env, 'D', arg);
        default:
            if (v.type == JS_VM_VAL_NULL) return NULL;
            if (v.type == JS_VM_VAL_OBJECT) return v.o;
            if (v.type == JS_VM_VAL_INT) { arg.i = v.i; return js_vm_box_jvalue_arg(env, 'I', arg); }
            if (v.type == JS_VM_VAL_LONG) { arg.j = v.l; return js_vm_box_jvalue_arg(env, 'J', arg); }
            if (v.type == JS_VM_VAL_FLOAT) { arg.f = v.f; return js_vm_box_jvalue_arg(env, 'F', arg); }
            if (v.type == JS_VM_VAL_DOUBLE) { arg.d = v.d; return js_vm_box_jvalue_arg(env, 'D', arg); }
            return NULL;
    }
}

static jobject js_vm_default_return(JNIEnv *env, jstring descriptor) {
    char ret_desc = js_vm_return_descriptor(env, descriptor);
    jobject result = js_vm_box_return(env, ret_desc, js_vm_null_value());
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return NULL;
    }
    return result;
}

JS_HIDDEN jobject js_vm_fail_closed(JNIEnv *env, const char *reason) {
    jclass secCls = js_jni_cache.initialized ? js_jni_cache.security_exception_class : (*env)->FindClass(env, js_secret_get(JS_SECRET_ID_SECURITY_EXCEPTION_CLASS));
    if (secCls) (*env)->ThrowNew(env, secCls, reason && reason[0] ? reason : "native VM execution failed");
    return NULL;
}





static jclass js_vm_load_class_with_loader(JNIEnv *env, jobject loader, const char *class_name) {
    if (!loader || !class_name || !class_name[0]) return NULL;
    if (class_name[0] == '[' || class_name[1] == 0) return NULL;
    char *binary_name = js_vm_binary_class_name(class_name);
    if (!binary_name) return NULL;
    jclass loader_cls = js_jni_cache.initialized ? js_jni_cache.class_loader_class : (*env)->FindClass(env, "java/lang/ClassLoader");
    if (!loader_cls) {
        free(binary_name);
        js_vm_clear_exception(env);
        return NULL;
    }
    jmethodID load_class = js_jni_cache.initialized ? js_jni_cache.class_loader_load_class : (*env)->GetMethodID(env, loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load_class) {
        free(binary_name);
        js_vm_clear_exception(env);
        return NULL;
    }
    jstring name = (*env)->NewStringUTF(env, binary_name);
    free(binary_name);
    if (!name) {
        js_vm_clear_exception(env);
        return NULL;
    }
    jobject cls = (*env)->CallObjectMethod(env, loader, load_class, name);
    if ((*env)->ExceptionCheck(env) || !cls) {
        js_vm_clear_exception(env);
        return NULL;
    }
    return (jclass)cls;
}

JS_HIDDEN jclass js_vm_find_registration_class(JNIEnv *env, const char *class_name) {
    if (!class_name || !class_name[0]) return NULL;
    jclass cls = (*env)->FindClass(env, class_name);
    if (cls || class_name[0] == '[' || class_name[1] == 0) return cls;
    js_vm_clear_exception(env);
    /* Prefer the loader of the obfuscated class that triggered the active VM
     * dispatch: it owns the application classpath and can resolve sibling
     * classes (including default-package classes) that the bootstrap-context
     * FindClass cannot see. */
    jobject active_host_loader = js_vm_get_active_host_loader();
    if (active_host_loader) {
        cls = js_vm_load_class_with_loader(env, active_host_loader, class_name);
        if (cls) return cls;
        js_vm_clear_exception(env);
    }
    jobject context_loader = js_vm_context_class_loader(env);
    if (context_loader) {
        cls = js_vm_load_class_with_loader(env, context_loader, class_name);
        if (cls) return cls;
    }
    char *loader_owner = sys_prop(env, "j.l");
    if (!loader_owner || !loader_owner[0]) {
        free(loader_owner);
        return NULL;
    }
    jclass helper_cls = (*env)->FindClass(env, loader_owner);
    if (!helper_cls) {
        js_vm_clear_exception(env);
        helper_cls = context_loader ? js_vm_load_class_with_loader(env, context_loader, loader_owner) : NULL;
    }
    free(loader_owner);
    if (!helper_cls) return NULL;
    jobject helper_loader = js_vm_helper_class_loader(env, helper_cls);
    if (helper_loader) {
        cls = js_vm_load_class_with_loader(env, helper_loader, class_name);
    }
    return cls;
}






static jobjectArray js_vm_build_nested_args(JNIEnv *env, jobject target, const jvalue *args, const char *arg_tags, int argc) {
    if (!env || !js_jni_cache.initialized || !js_jni_cache.object_class || argc < 0) return NULL;
    int extra = target ? 1 : 0;
    jobjectArray nested = (*env)->NewObjectArray(env, argc + extra, js_jni_cache.object_class, NULL);
    if ((*env)->ExceptionCheck(env) || !nested) return NULL;
    int index = 0;
    if (target) {
        (*env)->SetObjectArrayElement(env, nested, index++, target);
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    for (int i = 0; i < argc; i++) {
        jobject boxed = js_vm_box_jvalue_arg(env, arg_tags[i], args[i]);
        if ((*env)->ExceptionCheck(env)) return NULL;
        (*env)->SetObjectArrayElement(env, nested, index++, boxed);
        if (boxed) (*env)->DeleteLocalRef(env, boxed);
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    return nested;
}

static int js_vm_try_invoke_preloaded_nested(JNIEnv *env, js_vm_symbol_cache_entry *symbol, jobject target, const jvalue *args, js_vm_value *stack, int stack_cap, int *sp) {
    if (!env || !symbol || symbol->class_hash == 0ULL || symbol->meth_hash == 0ULL || symbol->sig_hash == 0ULL || symbol->is_constructor) return 0;
    js_vm_program *nested_program = js_vm_find_preloaded_program_by_method(symbol->class_hash, symbol->meth_hash, symbol->sig_hash);
    if (!nested_program) return 0;
    /* Decline native recursion past the depth bound so the caller falls back to
     * a normal JNI call of the target's Java dispatch stub; keeps the C stack
     * bounded for deeply recursive guest algorithms without changing results. */
    if (js_vm_nested_dispatch_depth >= JS_VM_NESTED_DISPATCH_MAX_DEPTH) return 0;
    if ((*env)->PushLocalFrame(env, 256) != 0) return -1;
    if (target && symbol->cls) {
        jclass target_cls = (*env)->GetObjectClass(env, target);
        if ((*env)->ExceptionCheck(env) || !target_cls) { (*env)->PopLocalFrame(env, NULL); return -1; }
        int same_class = (*env)->IsSameObject(env, target_cls, symbol->cls);
        (*env)->DeleteLocalRef(env, target_cls);
        if ((*env)->ExceptionCheck(env)) { (*env)->PopLocalFrame(env, NULL); return -1; }
        if (!same_class) { (*env)->PopLocalFrame(env, NULL); return 0; }
    }
    jobjectArray nested_args = js_vm_build_nested_args(env, target, args, symbol->arg_tags, symbol->argc);
    if ((*env)->ExceptionCheck(env) || !nested_args) { (*env)->PopLocalFrame(env, NULL); return -1; }
    js_vm_nested_dispatch_depth++;
    js_vm_object_result nested = js_vm_execute_prepared_program(env, nested_program, nested_args);
    js_vm_nested_dispatch_depth--;
    (*env)->DeleteLocalRef(env, nested_args);
    if ((*env)->ExceptionCheck(env) || !nested.ok) { (*env)->PopLocalFrame(env, NULL); return -1; }
    if ((char)symbol->ret_tag == 'V') { (*env)->PopLocalFrame(env, NULL); return 1; }
    js_vm_value nested_value;
    if (!js_vm_boxed_arg(env, nested.value, &nested_value)) { (*env)->PopLocalFrame(env, NULL); return -1; }
    jobject survivor = NULL;
    if (nested_value.type == JS_VM_VAL_OBJECT && nested_value.o) {
        survivor = (*env)->PopLocalFrame(env, nested_value.o);
        if ((*env)->ExceptionCheck(env) || !survivor) return -1;
        nested_value.o = survivor;
    } else {
        (*env)->PopLocalFrame(env, NULL);
    }
    int pushed = js_vm_push(stack, stack_cap, sp, nested_value);
    if (!pushed) js_vm_clear_value(&nested_value);
    return pushed ? 1 : -1;
}


JS_HIDDEN int js_vm_build_state_binding(jlong entry_token, const char *resource_path, unsigned char *out, int out_cap) {
    if (!out || out_cap <= 0) return 0;
    char layout_digest_hex[65];
    unsigned char layout_digest[32];
    unsigned char entry_integrity[4];
    int binding_len = 0;
    for (int i = 0; i < 32; i++) layout_digest[i] = JS_VBC4_LAYOUT_DIGEST_AT(i);
    for (int i = 0; i < 32; i++) snprintf(layout_digest_hex + (i * 2), sizeof(layout_digest_hex) - (size_t)(i * 2), "%02x", layout_digest[i]);
    js_vbc4_wipe_volatile(layout_digest, sizeof(layout_digest));
    layout_digest_hex[64] = 0;
    js_vm_write_clean_entry_integrity_bytes(entry_integrity);
    int written = snprintf((char*)out, (size_t)out_cap, "%llx", (unsigned long long)entry_token);
    if (written < 0 || written >= out_cap) written = out_cap - 1;
    binding_len = written;
    if (binding_len < out_cap) out[binding_len++] = 0;
    const char *binding_resource_path = resource_path ? resource_path : "";
    size_t resource_len = strlen(binding_resource_path);
    if (resource_len > (size_t)(out_cap - binding_len)) resource_len = (size_t)(out_cap - binding_len);
    memcpy(out + binding_len, binding_resource_path, resource_len);
    binding_len += (int)resource_len;
    if (binding_len < out_cap) out[binding_len++] = 0;
    written = snprintf((char*)out + binding_len, (size_t)(out_cap - binding_len), "%02x%02x%02x%02x", entry_integrity[0], entry_integrity[1], entry_integrity[2], entry_integrity[3]);
    js_vbc4_wipe_volatile(entry_integrity, sizeof(entry_integrity));
    if (written < 0) written = 0;
    if (written > out_cap - binding_len) written = out_cap - binding_len;
    binding_len += written;
    if (binding_len < out_cap) out[binding_len++] = 0;
    size_t layout_len = strlen(layout_digest_hex);
    if (layout_len > (size_t)(out_cap - binding_len)) layout_len = (size_t)(out_cap - binding_len);
    memcpy(out + binding_len, layout_digest_hex, layout_len);
    binding_len += (int)layout_len;
    return binding_len;
}

/* Execute an already-parsed VM program and box its return value into a Java object.
 * Returns {ok=1, value} on success (value may be NULL for void/null returns),
 * or {ok=0, NULL} if the interpreter rejected the program. */
JS_HIDDEN js_vm_object_result js_vm_execute_prepared_program(JNIEnv *env, js_vm_program *program, jobjectArray args) {
    js_vm_object_result result;
    result.ok = 0;
    result.value = NULL;
    char ret_desc = program && program->return_desc ? program->return_desc : 'V';
    js_vm_value ret = js_vm_null_value();
    int guest_frame_saved_count = js_vm_guest_frame_count;
    int guest_frame_pushed = js_vm_guest_frame_push(program);
    int ok = js_vm_execute_register(env, program, args, ret_desc, &ret);
    if (!ok) {
        if (program && program->original_owner && program->original_name && program->original_desc && !(*env)->ExceptionCheck(env)) {
            char reason[384];
            snprintf(reason, sizeof(reason), "native VM execution failed at %s#%s%s", program->original_owner, program->original_name, program->original_desc);
            if (js_vm_last_failure_pc >= 0) {
                snprintf(reason, sizeof(reason), "native VM execution failed at %s#%s%s pc=%d opcode=%d sp=%d raw=%d mask=%d epoch=%d cached=%d insns=%d step=%d limit=%d detail=%s", program->original_owner, program->original_name, program->original_desc, js_vm_last_failure_pc, js_vm_last_failure_opcode, js_vm_last_failure_sp, js_vm_last_failure_raw_opcode, js_vm_last_failure_mask, js_vm_last_failure_epoch, js_vm_last_failure_cached, js_vm_last_failure_insn_count, js_vm_last_failure_step, js_vm_last_failure_step_limit, js_vm_last_failure_detail);
            }
            js_vm_fail_closed(env, reason);
        }
        js_vm_clear_value(&ret);
        js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed);
        return result;
    }
    if ((*env)->ExceptionCheck(env)) { js_vm_clear_value(&ret); js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed); return result; }
    jobject boxed = js_vm_box_return(env, ret_desc, ret);
    js_vm_clear_value(&ret);
    if ((*env)->ExceptionCheck(env)) { js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed); return result; }
    result.ok = 1;
    result.value = boxed;
    js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed);
    return result;
}

JS_HIDDEN int js_vm_execute_hot_path_self_check(void) {
    return js_check_trampoline((const void*)js_vm_execute_resource) &&
        js_check_trampoline((const void*)js_vm_parse_program) &&
        js_check_trampoline((const void*)js_vbc4_hmac_sha256_with_nonce) &&
        js_check_trampoline((const void*)js_vm_execute) &&
        js_check_trampoline((const void*)js_vm_invoke_method) &&
        js_check_trampoline((const void*)js_vm_box_return) &&
        js_check_trampoline((const void*)js_vbc4_decrypt_block);
}

JS_HIDDEN int js_vm_resource_integrity_clean(void) {
    return js_vm_entry_integrity_state() == js_vm_clean_entry_integrity_state();
}

static jobject js_vm_receiver_class_from_args(JNIEnv *env, jobjectArray args) {
    if (!env || !args) return NULL;
    jsize argc = (*env)->GetArrayLength(env, args);
    if ((*env)->ExceptionCheck(env) || argc <= 0) { js_vm_clear_exception(env); return NULL; }
    jobject receiver = (*env)->GetObjectArrayElement(env, args, 0);
    if ((*env)->ExceptionCheck(env) || !receiver) { js_vm_clear_exception(env); return NULL; }
    jobject cls = (*env)->GetObjectClass(env, receiver);
    if ((*env)->ExceptionCheck(env)) { js_vm_clear_exception(env); return NULL; }
    return cls;
}

static int js_vm_cp_value(JNIEnv *env, js_vm_program *p, jobjectArray args, int cp_idx, int opcode, js_vm_value *out) {
    if (cp_idx < 0 || cp_idx >= p->cp_count) return 0;
    js_vm_cp cp;
    if (!js_vm_decode_cp_entry(p, cp_idx, &cp)) return 0;
    int ok = 0;
    switch (opcode) {
        case JS_VM_LCONST:
        case JS_VM_LDC_LONG:
            ok = cp.type == JS_VM_CP_LONG;
            if (ok) *out = js_vm_long_value(cp.l);
            break;
        case JS_VM_DCONST:
        case JS_VM_LDC_DOUBLE:
            ok = cp.type == JS_VM_CP_DOUBLE;
            if (ok) *out = js_vm_double_value(cp.d);
            break;
        case JS_VM_LDC_INT:
            ok = cp.type == JS_VM_CP_INT;
            if (ok) *out = js_vm_int_value(cp.i);
            break;
        case JS_VM_LDC_FLOAT:
            ok = cp.type == JS_VM_CP_FLOAT;
            if (ok) *out = js_vm_float_value(cp.f);
            break;
        case JS_VM_LDC_STRING:
            ok = cp.type == JS_VM_CP_STRING && cp.s;
            if (ok) {
                *out = js_vm_object_value((*env)->NewStringUTF(env, cp.s));
                ok = !(*env)->ExceptionCheck(env);
            }
            break;
        case JS_VM_LDC_HANDLE:
            ok = cp.type == JS_VM_CP_STRING && cp.s;
            if (ok) {
                char *helper_owner = js_first_loader_owner_from_property(env);
                if (!helper_owner || !helper_owner[0]) { free(helper_owner); helper_owner = js_helper_owner("Jni", "Micro", "kernel", "Helper"); }
                jclass helper_cls = helper_owner ? js_vm_find_class_name(env, helper_owner) : NULL;
                jmethodID resolve_mid = helper_cls ? (*env)->GetStaticMethodID(env, helper_cls, "resolveVmMethodHandle", "(Ljava/lang/String;)Ljava/lang/invoke/MethodHandle;") : NULL;
                jstring encoded = (*env)->NewStringUTF(env, cp.s);
                jobject handle = (helper_cls && resolve_mid && encoded) ? (*env)->CallStaticObjectMethod(env, helper_cls, resolve_mid, encoded) : NULL;
                free(helper_owner);
                *out = js_vm_object_value(handle);
                ok = !(*env)->ExceptionCheck(env) && handle;
            }
            break;
        case JS_VM_LDC_TYPE:
            ok = cp.type == JS_VM_CP_STRING && cp.s;
            if (ok) {
                jobject cls = NULL;
                if (js_vm_original_method_is_instance(p) && js_vm_ldc_type_matches_original_owner(cp.s, p)) cls = js_vm_receiver_class_from_args(env, args);
                if (!cls) cls = js_vm_find_class_name(env, cp.s);
                *out = js_vm_object_value(cls);
                ok = !(*env)->ExceptionCheck(env) && !js_vm_value_is_null(*out);
            }
            break;
        default:
            ok = 0;
            break;
    }
    js_vm_clear_decoded_cp(&cp);
    return ok;
}

static int js_vm_pop_jni_args(JNIEnv *env, js_vm_value *stack, int *sp, const char *desc, jvalue **args_out, int *argc_out) {
    char *tags = NULL;
    int argc = 0;
    jvalue *args = NULL;
    if (!js_vm_descriptor_arg_tags(desc, &tags, &argc)) return 0;
    if (argc > 0) {
        args = (jvalue*)calloc((size_t)argc, sizeof(jvalue));
        if (!args) { free(tags); return 0; }
    }
    for (int i = argc - 1; i >= 0; i--) {
        js_vm_value value;
        if (!js_vm_pop(stack, sp, &value) || !js_vm_to_jvalue(env, value, tags[i], &args[i])) {
            free(tags);
            free(args);
            return 0;
        }
    }
    free(tags);
    *args_out = args;
    *argc_out = argc;
    return 1;
}

static int js_vm_pop_jni_args_cached(JNIEnv *env, js_vm_value *stack, int *sp, const char *tags, int argc, jvalue **args_out) {
    jvalue *args = NULL;
    if (!tags || argc < 0 || !args_out) return 0;
    if (argc > 0) {
        args = (jvalue*)calloc((size_t)argc, sizeof(jvalue));
        if (!args) return 0;
    }
    for (int i = argc - 1; i >= 0; i--) {
        js_vm_value value;
        if (!js_vm_pop(stack, sp, &value) || !js_vm_to_jvalue(env, value, tags[i], &args[i])) {
            free(args);
            return 0;
        }
    }
    *args_out = args;
    return 1;
}
static int js_vm_field_access(JNIEnv *env, js_vm_program *p, int cp_idx, int opcode, js_vm_value *stack, int stack_cap, int *sp) {
    jclass cls;
    jfieldID fid;
    int symbol_kind;
    js_vm_symbol_cache_entry *cached_symbol;
    js_vm_value value, target;
    jvalue jv;
    char tag;
    memset(&jv, 0, sizeof(jv));
    (void)stack_cap;
    symbol_kind = (opcode == JS_VM_GETSTATIC || opcode == JS_VM_PUTSTATIC) ? 2 : 3;
    cached_symbol = js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind);
    if (!cached_symbol) {
        if (!js_vm_resolve_field_symbol(env, p, cp_idx, symbol_kind)) return 0;
        cached_symbol = js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind);
    }
    if (!cached_symbol || !cached_symbol->fid || !cached_symbol->cls) return 0;
    cls = cached_symbol->cls;
    fid = cached_symbol->fid;
    tag = (char)cached_symbol->tag;
    if (opcode == JS_VM_GETSTATIC || opcode == JS_VM_PUTSTATIC) {
        if (opcode == JS_VM_GETSTATIC) {
            switch (tag) {
                case 'Z': value = js_vm_int_value((*env)->GetStaticBooleanField(env, cls, fid) ? 1 : 0); break;
                case 'B': value = js_vm_int_value((jint)(*env)->GetStaticByteField(env, cls, fid)); break;
                case 'S': value = js_vm_int_value((jint)(*env)->GetStaticShortField(env, cls, fid)); break;
                case 'C': value = js_vm_int_value((jint)(*env)->GetStaticCharField(env, cls, fid)); break;
                case 'I': value = js_vm_int_value((*env)->GetStaticIntField(env, cls, fid)); break;
                case 'J': value = js_vm_long_value((*env)->GetStaticLongField(env, cls, fid)); break;
                case 'F': value = js_vm_float_value((*env)->GetStaticFloatField(env, cls, fid)); break;
                case 'D': value = js_vm_double_value((*env)->GetStaticDoubleField(env, cls, fid)); break;
                default: {
                    jobject object_value = (*env)->GetStaticObjectField(env, cls, fid);
                    value = js_vm_object_value(object_value);
                    break;
                }
            }
            if ((*env)->ExceptionCheck(env)) return 0;
            return js_vm_push(stack, stack_cap, sp, value);
        }
        if (!js_vm_pop(stack, sp, &value) || !js_vm_to_jvalue(env, value, tag, &jv)) return 0;
        switch (tag) {
            case 'Z': (*env)->SetStaticBooleanField(env, cls, fid, jv.z); break;
            case 'B': (*env)->SetStaticByteField(env, cls, fid, jv.b); break;
            case 'S': (*env)->SetStaticShortField(env, cls, fid, jv.s); break;
            case 'C': (*env)->SetStaticCharField(env, cls, fid, jv.c); break;
            case 'I': (*env)->SetStaticIntField(env, cls, fid, jv.i); break;
            case 'J': (*env)->SetStaticLongField(env, cls, fid, jv.j); break;
            case 'F': (*env)->SetStaticFloatField(env, cls, fid, jv.f); break;
            case 'D': (*env)->SetStaticDoubleField(env, cls, fid, jv.d); break;
            default: (*env)->SetStaticObjectField(env, cls, fid, jv.l); break;
        }
        return !(*env)->ExceptionCheck(env);
    }
    if (opcode == JS_VM_GETFIELD) {
        if (!js_vm_pop(stack, sp, &target)) return 0;
        if (target.type != JS_VM_VAL_OBJECT || !target.o) return js_vm_throw_new(env, "java/lang/NullPointerException", "getfield on null");
        switch (tag) {
            case 'Z': value = js_vm_int_value((*env)->GetBooleanField(env, target.o, fid) ? 1 : 0); break;
            case 'B': value = js_vm_int_value((jint)(*env)->GetByteField(env, target.o, fid)); break;
            case 'S': value = js_vm_int_value((jint)(*env)->GetShortField(env, target.o, fid)); break;
            case 'C': value = js_vm_int_value((jint)(*env)->GetCharField(env, target.o, fid)); break;
            case 'I': value = js_vm_int_value((*env)->GetIntField(env, target.o, fid)); break;
            case 'J': value = js_vm_long_value((*env)->GetLongField(env, target.o, fid)); break;
            case 'F': value = js_vm_float_value((*env)->GetFloatField(env, target.o, fid)); break;
            case 'D': value = js_vm_double_value((*env)->GetDoubleField(env, target.o, fid)); break;
            default: value = js_vm_object_value((*env)->GetObjectField(env, target.o, fid)); break;
        }
        return !(*env)->ExceptionCheck(env) && js_vm_push(stack, stack_cap, sp, value);
    }
    if (!js_vm_pop(stack, sp, &value) || !js_vm_pop(stack, sp, &target)) return 0;
    if (target.type != JS_VM_VAL_OBJECT || !target.o) return js_vm_throw_new(env, "java/lang/NullPointerException", "putfield on null");
    if (!js_vm_to_jvalue(env, value, tag, &jv)) return 0;
    switch (tag) {
        case 'Z': (*env)->SetBooleanField(env, target.o, fid, jv.z); break;
        case 'B': (*env)->SetByteField(env, target.o, fid, jv.b); break;
        case 'S': (*env)->SetShortField(env, target.o, fid, jv.s); break;
        case 'C': (*env)->SetCharField(env, target.o, fid, jv.c); break;
        case 'I': (*env)->SetIntField(env, target.o, fid, jv.i); break;
        case 'J': (*env)->SetLongField(env, target.o, fid, jv.j); break;
        case 'F': (*env)->SetFloatField(env, target.o, fid, jv.f); break;
        case 'D': (*env)->SetDoubleField(env, target.o, fid, jv.d); break;
        default: (*env)->SetObjectField(env, target.o, fid, jv.l); break;
    }
    return !(*env)->ExceptionCheck(env);
}
static void js_vm_replace_uninit_refs(js_vm_value *stack, int sp, js_vm_value *locals, int local_cap, int id, jobject object) {
    for (int i = 0; i < sp; i++) {
        if (stack[i].type == JS_VM_VAL_UNINIT && stack[i].uninit_id == id) {
            js_vm_clear_value(&stack[i]);
            stack[i] = js_vm_object_value(object);
        }
    }
    for (int i = 0; i < local_cap; i++) {
        if (locals[i].type == JS_VM_VAL_UNINIT && locals[i].uninit_id == id) {
            js_vm_clear_value(&locals[i]);
            locals[i] = js_vm_object_value(object);
        }
    }
}

static int js_vm_sb_append_string(JNIEnv *env, jobject sb, jmethodID append_mid, jstring s) {
    if (!sb || !append_mid || !s) return 0;
    (*env)->CallObjectMethod(env, sb, append_mid, s);
    return !(*env)->ExceptionCheck(env);
}

static int js_vm_sb_append_utf(JNIEnv *env, jobject sb, jmethodID append_mid, const char *start, const char *end) {
    char *part = js_vm_copy_cstr_range(start, end);
    if (!part) return 0;
    jstring s = (*env)->NewStringUTF(env, part);
    free(part);
    if (!s) return 0;
    return js_vm_sb_append_string(env, sb, append_mid, s);
}

static int js_vm_invoke_dynamic_static_target(JNIEnv *env, const char *indy, js_vm_value *stack, int stack_cap, int *sp) {
    char *owned = NULL;
    char *parts[6];
    char *cursor = NULL;
    char *tags = NULL;
    jvalue *args = NULL;
    int argc = 0;
    jclass cls = NULL;
    jmethodID mid = NULL;
    char ret_tag = 'V';
    jvalue result;
    int ok = 0;
    memset(&result, 0, sizeof(result));
    if (!env || !indy || strncmp(indy, "mhstatic|", 9) != 0) return 0;
    owned = js_strdup(indy);
    if (!owned) return 0;
    cursor = owned;
    for (int i = 0; i < 6; i++) {
        parts[i] = cursor;
        char *bar = strchr(cursor, '|');
        if (i < 5) {
            if (!bar) goto done;
            *bar = 0;
            cursor = bar + 1;
        } else if (bar) {
            goto done;
        }
    }
    if (strcmp(parts[0], "mhstatic") != 0 || !parts[3][0] || !parts[4][0] || !parts[5][0]) goto done;
    if (strcmp(parts[2], parts[5]) != 0) goto done;
    if (!js_vm_descriptor_arg_tags(parts[5], &tags, &argc)) goto done;
    if (!js_vm_pop_jni_args_cached(env, stack, sp, tags, argc, &args)) goto done;
    cls = js_vm_find_class_name(env, parts[3]);
    if ((*env)->ExceptionCheck(env) || !cls) goto done;
    mid = (*env)->GetStaticMethodID(env, cls, parts[4], parts[5]);
    if ((*env)->ExceptionCheck(env) || !mid) goto done;
    ret_tag = js_vm_descriptor_return_tag(parts[5]);
    switch (ret_tag) {
        case 'V': (*env)->CallStaticVoidMethodA(env, cls, mid, args); break;
        case 'Z': result.z = (*env)->CallStaticBooleanMethodA(env, cls, mid, args); break;
        case 'B': result.b = (*env)->CallStaticByteMethodA(env, cls, mid, args); break;
        case 'S': result.s = (*env)->CallStaticShortMethodA(env, cls, mid, args); break;
        case 'C': result.c = (*env)->CallStaticCharMethodA(env, cls, mid, args); break;
        case 'I': result.i = (*env)->CallStaticIntMethodA(env, cls, mid, args); break;
        case 'J': result.j = (*env)->CallStaticLongMethodA(env, cls, mid, args); break;
        case 'F': result.f = (*env)->CallStaticFloatMethodA(env, cls, mid, args); break;
        case 'D': result.d = (*env)->CallStaticDoubleMethodA(env, cls, mid, args); break;
        default: result.l = (*env)->CallStaticObjectMethodA(env, cls, mid, args); break;
    }
    if ((*env)->ExceptionCheck(env)) goto done;
    ok = js_vm_push_call_result(env, stack, stack_cap, sp, ret_tag, result);
done:
    free(tags);
    free(args);
    if (owned) { js_vbc4_wipe_volatile(owned, strlen(owned)); free(owned); }
    return ok;
}

static int js_vm_invoke_dynamic(JNIEnv *env, js_vm_program *p, int cp_idx, js_vm_value *stack, int stack_cap, int *sp) {
    char *indy = js_vm_cp_string_owned(p, cp_idx);
    const char *first_bar, *second_bar, *call_start, *call_end, *colon, *recipe_start = NULL, *recipe_end = NULL, *const_start = NULL;
    char *desc = NULL;
    char *tags = NULL;
    int argc = 0;
    js_vm_value *values = NULL;
    jclass sb_cls;
    jmethodID sb_init, sb_append, sb_to_string;
    jobject sb = NULL, result = NULL;
    int ok = 1;
    int arg_index = 0;
    int const_index = 0;
    if (!indy) return 0;

    if (strncmp(indy, "mhstatic|", 9) == 0) {
        ok = js_vm_invoke_dynamic_static_target(env, indy, stack, stack_cap, sp);
        goto js_vm_invoke_dynamic_done;
    }

    if (strncmp(indy, "lambda|", 7) == 0) {
        char *parts[7];
        char *cursor = indy;
        int part_count = 0;
        while (part_count < 7) {
            parts[part_count++] = cursor;
            char *bar = strchr(cursor, '|');
            if (!bar) break;
            *bar = 0;
            cursor = bar + 1;
        }
        if (part_count == 7) {
            desc = js_strdup(parts[2]);
            if (!desc || !js_vm_descriptor_arg_tags(desc, &tags, &argc)) { ok = 0; goto js_vm_invoke_dynamic_done; }
            if (!js_jni_cache.initialized || !js_jni_cache.object_class) { ok = 0; goto js_vm_invoke_dynamic_done; }
            jobjectArray captured = (*env)->NewObjectArray(env, argc, js_jni_cache.object_class, NULL);
            if ((*env)->ExceptionCheck(env) || (argc > 0 && !captured)) { ok = 0; goto js_vm_invoke_dynamic_done; }
            values = argc > 0 ? (js_vm_value*)calloc((size_t)argc, sizeof(js_vm_value)) : NULL;
            if (argc > 0 && !values) { ok = 0; goto js_vm_invoke_dynamic_done; }
            for (int i = argc - 1; i >= 0; i--) {
                if (!js_vm_pop(stack, sp, &values[i])) { ok = 0; break; }
            }
            for (int i = 0; ok && i < argc; i++) {
                jobject boxed = js_vm_box_return(env, tags[i], values[i]);
                if ((*env)->ExceptionCheck(env)) { ok = 0; break; }
                (*env)->SetObjectArrayElement(env, captured, i, boxed);
                if ((*env)->ExceptionCheck(env)) { ok = 0; }
            }
            if (ok) {
                char *helper_owner = js_first_loader_owner_from_property(env);
                if (!helper_owner || !helper_owner[0]) { free(helper_owner); helper_owner = js_helper_owner("Jni", "Micro", "kernel", "Helper"); }
                jclass helper_cls = helper_owner ? js_vm_find_class_name(env, helper_owner) : NULL;
                jmethodID create_mid = helper_cls ? (*env)->GetStaticMethodID(env, helper_cls, "createSamLambda", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I[Ljava/lang/Object;)Ljava/lang/Object;") : NULL;
                jstring sam_name = (*env)->NewStringUTF(env, parts[1]);
                jstring factory_desc = (*env)->NewStringUTF(env, parts[2]);
                jstring owner = (*env)->NewStringUTF(env, parts[4]);
                jstring name = (*env)->NewStringUTF(env, parts[5]);
                jstring impl_desc = (*env)->NewStringUTF(env, parts[6]);
                jint impl_tag = (jint)atoi(parts[3]);
                result = (helper_cls && create_mid && sam_name && factory_desc && owner && name && impl_desc) ? (*env)->CallStaticObjectMethod(env, helper_cls, create_mid, sam_name, factory_desc, owner, name, impl_desc, impl_tag, captured) : NULL;
                free(helper_owner);
                ok = !(*env)->ExceptionCheck(env) && result && js_vm_push(stack, stack_cap, sp, js_vm_object_value(result));
            }
        } else {
            ok = 0;
        }
        goto js_vm_invoke_dynamic_done;
    }

    first_bar = strchr(indy, '|');
    call_start = first_bar ? first_bar + 1 : indy;
    second_bar = first_bar ? strchr(call_start, '|') : NULL;
    call_end = second_bar ? second_bar : indy + strlen(indy);
    colon = memchr(call_start, ':', (size_t)(call_end - call_start));
    if (!colon) { ok = 0; goto js_vm_invoke_dynamic_done; }
    desc = js_vm_copy_cstr_range(colon + 1, call_end);
    if (!desc) { ok = 0; goto js_vm_invoke_dynamic_done; }
    if (!js_vm_descriptor_arg_tags(desc, &tags, &argc)) { ok = 0; goto js_vm_invoke_dynamic_done; }
    values = argc > 0 ? (js_vm_value*)calloc((size_t)argc, sizeof(js_vm_value)) : NULL;
    if (argc > 0 && !values) { ok = 0; goto js_vm_invoke_dynamic_done; }
    for (int i = argc - 1; i >= 0; i--) {
        if (!js_vm_pop(stack, sp, &values[i])) { ok = 0; break; }
    }
    if (ok) {
        if (!js_jni_cache.initialized) { ok = 0; goto js_vm_invoke_dynamic_done; }
        sb_cls = js_jni_cache.string_builder_class;
        sb_init = js_jni_cache.string_builder_init;
        sb_append = js_jni_cache.string_builder_append_string;
        sb_to_string = js_jni_cache.string_builder_to_string;
        sb = (sb_cls && sb_init) ? (*env)->NewObject(env, sb_cls, sb_init) : NULL;
        if ((*env)->ExceptionCheck(env) || !sb || !sb_append || !sb_to_string) ok = 0;
    }
    if (ok && first_bar && strstr(indy, "StringConcatFactory") && second_bar) {
        recipe_start = second_bar + 1;
        recipe_end = js_vm_part_end(recipe_start);
        const_start = (*recipe_end == '|') ? recipe_end + 1 : NULL;
        const char *cursor2 = recipe_start;
        while (ok && cursor2 < recipe_end) {
            const char *run = cursor2;
            while (run < recipe_end && *run != 1 && *run != 2) run++;
            if (run > cursor2) ok = js_vm_sb_append_utf(env, sb, sb_append, cursor2, run);
            if (!ok || run >= recipe_end) break;
            if (*run == 1) {
                if (arg_index < argc) { ok = js_vm_sb_append_string(env, sb, sb_append, js_vm_value_to_string_for_tag(env, values[arg_index], tags[arg_index])); arg_index++; }
            } else if (*run == 2) {
                if (const_start) {
                    const char *ce = js_vm_part_end(const_start);
                    if (const_index++ >= 0) ok = js_vm_sb_append_utf(env, sb, sb_append, const_start, ce);
                    const_start = (*ce == '|') ? ce + 1 : NULL;
                }
            }
            cursor2 = run + 1;
        }
    } else if (ok) {
        for (int i = 0; ok && i < argc; i++) ok = js_vm_sb_append_string(env, sb, sb_append, js_vm_value_to_string_for_tag(env, values[i], tags[i]));
    }
    if (ok) {
        result = (*env)->CallObjectMethod(env, sb, sb_to_string);
        ok = !(*env)->ExceptionCheck(env) && js_vm_push(stack, stack_cap, sp, js_vm_object_value(result));
    }
js_vm_invoke_dynamic_done:
    free(desc);
    free(tags);
    js_vm_clear_value_range(values, argc);
    free(values);
    if (indy) { js_vbc4_wipe_volatile(indy, strlen(indy)); free(indy); }
    return ok;
}

static jobject js_vm_throwable_from_value(JNIEnv *env, js_vm_value value) {
    if (value.type == JS_VM_VAL_OBJECT && value.o) {
        if (js_jni_cache.initialized && js_jni_cache.throwable_class && (*env)->IsInstanceOf(env, value.o, js_jni_cache.throwable_class)) return value.o;
    }
    if (!js_jni_cache.initialized || !js_jni_cache.runtime_exception_class || !js_jni_cache.runtime_exception_init) return NULL;
    jstring msg = js_vm_value_to_string(env, value);
    return (*env)->NewObject(env, js_jni_cache.runtime_exception_class, js_jni_cache.runtime_exception_init, msg);
}

static int js_vm_handle_exception(JNIEnv *env, js_vm_program *p, js_vm_value *stack, int stack_cap, int *sp, int *pc, jobject thrown, int fault_pc) {
    if (!thrown) return 0;
    for (int i = 0; i < p->exception_count; i++) {
        js_vm_exception active_exception = js_vm_load_resident_exception(p, i);
        js_vm_exception *ex = &active_exception;
        if (fault_pc < ex->start || fault_pc >= ex->end) continue;
        if (ex->type_cp != 0) {
            int cp_idx = ex->type_cp - 1;
            char *catch_type = js_vm_cp_string_owned(p, cp_idx);
            jclass catch_cls = catch_type ? js_vm_find_class_name(env, catch_type) : NULL;
            if (catch_type) { js_vbc4_wipe_volatile(catch_type, strlen(catch_type)); free(catch_type); }
            if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); continue; }
            if (!catch_cls || !(*env)->IsInstanceOf(env, thrown, catch_cls)) continue;
        }
        js_vm_clear_value_range(stack, *sp);
        *sp = 0;
        if (!js_vm_push(stack, stack_cap, sp, js_vm_object_value(thrown))) return 0;
        *pc = ex->handler;
        return 1;
    }
    return 0;
}

/* Flattened macro dispatch intentionally avoids static target tables and C switch dispatch. */
static uint32_t js_vm_dispatch_salt(const js_vm_program *program, int pc) {
    uint32_t state = JS_VBC4_DISPATCH_MIX_A ^ (uint32_t)pc;
    if (program) {
        state ^= (uint32_t)program->insn_count * JS_VBC4_DISPATCH_MIX_B;
        state ^= ((uint32_t)program->exception_count << 11) ^ ((uint32_t)program->cp_count << 19);
        state ^= (uint32_t)program->nonce[(pc & 15)] << 24;
    }
    state ^= state >> 16;
    state *= 0x7FEB352Du;
    state ^= state >> 15;
    state *= 0x846CA68Bu;
    return state ^ (state >> 16);
}

static int js_vm_case_match(jint active_opcode, jint candidate_opcode, uint32_t salt) {
    uint32_t mask = (salt ^ JS_VBC4_DISPATCH_MIX_C) | 1u;
    uint32_t mixed_active = (((uint32_t)active_opcode) ^ mask) + (mask << 1);
    uint32_t mixed_candidate = (((uint32_t)candidate_opcode) ^ mask) + (mask << 1);
    /* Branchless constant-time equality: avoids a data-dependent compare/branch
     * (sete / conditional jump) on the per-opcode dispatch hot path, so an attacker
     * tracing branch outcomes (BTB / single-step) cannot tell which candidate matched
     * from the comparison itself. diff==0 -> 1, otherwise -> 0, with no branch. */
    uint32_t diff = mixed_active ^ mixed_candidate;
    /* (diff | -diff) has its MSB set iff diff != 0; invert that bit so equality
     * yields 1 and inequality yields 0. Pure data-flow, no comparison branch. */
    return (int)(1u ^ (((diff | ((~diff) + 1u)) >> 31) & 1u));
}

static uint32_t js_vm_dispatch_drift_step(const js_vm_program *program, uint32_t drift_state, int dispatch_step, int pc, int sp) {
    uint32_t state = drift_state ^ JS_VBC4_DISPATCH_MIX_C ^ (uint32_t)(dispatch_step * (JS_VBC4_DISPATCH_MIX_A | 1u));
    state ^= ((uint32_t)pc << 16) ^ ((uint32_t)sp & 0xFFFFu);
    if (program) {
        state ^= (uint32_t)program->nonce[(dispatch_step + pc) & 15] << 24;
        state ^= (uint32_t)program->insn_count * (JS_VBC4_DISPATCH_MIX_B | 1u);
    }
    state ^= state >> 15;
    state *= 0x2C1B3C6Du;
    state ^= state >> 12;
    state *= 0x297A2D39u;
    return state ^ (state >> 16);
}

static int js_vm_dispatch_rotation_due(const js_vm_program *program, uint32_t drift_state, int dispatch_step, int pc, int sp) {
    uint32_t gate = drift_state ^ js_vm_program_path_digest(program) ^ (uint32_t)(dispatch_step * 0x9E3779B1u);
    gate ^= ((uint32_t)pc << 9) ^ ((uint32_t)sp << 3);
    gate ^= gate >> 16;
    gate *= 0x7FEB352Du;
    uint32_t interval = 3u + (gate & 0x0Fu);
    uint32_t phase = (gate >> 8) % interval;
    int fixed_mask_due = ((dispatch_step & JS_VBC4_DISPATCH_STEP_MASK) == 0);
    return fixed_mask_due || (((uint32_t)dispatch_step + phase) % interval) == 0u;
}

static uint32_t js_vm_method_local_salt(const js_vm_program *program, uint32_t salt) {
    uint32_t profile = program ? program->method_local_profile : 0u;
    if (profile == 0u) return salt;
    salt ^= profile + JS_VBC4_DISPATCH_MIX_A + (salt << 7) + (salt >> 3);
    salt ^= salt >> 16;
    salt *= 0x7FEB352Du;
    return salt ^ (salt >> 15);
}

static uint32_t js_vm_dispatch_progress_salt(const js_vm_program *program, int pc, uint32_t drift_state) {
    uint32_t salt = js_vm_dispatch_salt(program, pc);
    salt ^= drift_state + 0xA5A5A5A5u + (salt << 6) + (salt >> 2);
    return js_vm_method_local_salt(program, salt);
}

static jobject js_vm_load_class_from_args(JNIEnv *env, jobject loader, jmethodID mid, const jvalue *args, int argc) {
    if (!env || !loader || !mid || !args || argc != 1 || !args[0].l) return NULL;
    if (!js_jni_cache.initialized || !js_jni_cache.class_loader_class || !js_jni_cache.string_class) {
        return (*env)->CallObjectMethodA(env, loader, mid, args);
    }
    if (!(*env)->IsInstanceOf(env, loader, js_jni_cache.class_loader_class) || !(*env)->IsInstanceOf(env, args[0].l, js_jni_cache.string_class)) {
        return (*env)->CallObjectMethodA(env, loader, mid, args);
    }
    jvalue normalized[1];
    normalized[0] = args[0];
    jstring normalized_name_ref = NULL;
    const char *raw_name = j2c(env, (jstring)args[0].l);
    if (!raw_name) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    if (strchr(raw_name, '/') != NULL) {
        char *binary_name = js_vm_binary_class_name(raw_name);
        if (!binary_name) {
            rls(env, (jstring)args[0].l, raw_name);
            return NULL;
        }
        normalized_name_ref = (*env)->NewStringUTF(env, binary_name);
        free(binary_name);
        if ((*env)->ExceptionCheck(env) || !normalized_name_ref) {
            rls(env, (jstring)args[0].l, raw_name);
            return NULL;
        }
        normalized[0].l = normalized_name_ref;
    }
    rls(env, (jstring)args[0].l, raw_name);
    jobject loaded = (*env)->CallObjectMethodA(env, loader, mid, normalized);
    if (normalized_name_ref) (*env)->DeleteLocalRef(env, normalized_name_ref);
    return loaded;
}

static jobject js_vm_define_class_from_args(JNIEnv *env, jobject loader, const jvalue *args, int argc) {
    if (!env || !loader || !args || argc != 4 || !args[1].l) return NULL;
    jvalue normalized[4];
    memcpy(normalized, args, sizeof(normalized));
    if (!js_jni_cache.initialized || !js_jni_cache.class_loader_class || !js_jni_cache.byte_array_class || !js_jni_cache.class_loader_define_class) {
        js_vm_throw_new(env, "java/lang/LinkageError", "defineClass method cache is not initialized");
        return NULL;
    }
    if (!(*env)->IsInstanceOf(env, loader, js_jni_cache.class_loader_class)) {
        js_vm_throw_new(env, "java/lang/LinkageError", "defineClass receiver is not a ClassLoader");
        return NULL;
    }
    int name0 = !normalized[0].l || (js_jni_cache.initialized && js_jni_cache.string_class && (*env)->IsInstanceOf(env, normalized[0].l, js_jni_cache.string_class));
    int bytes1 = normalized[1].l && (*env)->IsInstanceOf(env, normalized[1].l, js_jni_cache.byte_array_class);
    int bytes0 = normalized[0].l && (*env)->IsInstanceOf(env, normalized[0].l, js_jni_cache.byte_array_class);
    int name1 = !normalized[1].l || (js_jni_cache.initialized && js_jni_cache.string_class && (*env)->IsInstanceOf(env, normalized[1].l, js_jni_cache.string_class));
    if (!name0 && !bytes1 && bytes0 && name1) {
        jvalue tmp = normalized[0];
        normalized[0] = normalized[1];
        normalized[1] = tmp;
        name0 = !normalized[0].l || (js_jni_cache.initialized && js_jni_cache.string_class && (*env)->IsInstanceOf(env, normalized[0].l, js_jni_cache.string_class));
        bytes1 = normalized[1].l && (*env)->IsInstanceOf(env, normalized[1].l, js_jni_cache.byte_array_class);
    }
    if (!name0 || !bytes1) {
        js_vm_throw_new(env, "java/lang/LinkageError", "invalid defineClass argument layout");
        return NULL;
    }
    jstring normalized_name_ref = NULL;
    if (normalized[0].l) {
        jstring original_name_ref = (jstring)normalized[0].l;
        const char *raw_name = j2c(env, original_name_ref);
        if (!raw_name) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return NULL;
        }
        if (strchr(raw_name, '/') != NULL) {
            char *binary_name = js_vm_binary_class_name(raw_name);
            if (!binary_name) {
                rls(env, original_name_ref, raw_name);
                return NULL;
            }
            normalized_name_ref = (*env)->NewStringUTF(env, binary_name);
            free(binary_name);
            if ((*env)->ExceptionCheck(env) || !normalized_name_ref) {
                rls(env, original_name_ref, raw_name);
                return NULL;
            }
            normalized[0].l = normalized_name_ref;
        }
        rls(env, original_name_ref, raw_name);
    }
    jbyteArray byte_array = (jbyteArray)normalized[1].l;
    jint offset = normalized[2].i;
    jint length = normalized[3].i;
    jsize array_len = (*env)->GetArrayLength(env, byte_array);
    if ((*env)->ExceptionCheck(env) || offset < 0 || length < 0 || offset > array_len || length > array_len - offset) {
        if (normalized_name_ref) (*env)->DeleteLocalRef(env, normalized_name_ref);
        return NULL;
    }
    jobject defined = (*env)->CallNonvirtualObjectMethodA(env, loader, js_jni_cache.class_loader_class, js_jni_cache.class_loader_define_class, normalized);
    if (normalized_name_ref) (*env)->DeleteLocalRef(env, normalized_name_ref);
    return defined;
}

static int js_vm_rebind_self_call_locals(JNIEnv *env, js_vm_symbol_cache_entry *symbol, jobject target, const jvalue *args, js_vm_value *locals, int local_cap, uint32_t local_perm_mul, uint32_t local_perm_add) {
    if (!symbol || !locals || local_cap <= 0 || !symbol->arg_tags || symbol->argc < 0) return 0;
    int slot = 0;
    if (target) {
        locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_object_value(target);
    }
    for (int i = 0; i < symbol->argc; i++) {
        if (slot >= local_cap) return 0;
        char tag = symbol->arg_tags[i];
        switch (tag) {
            case 'Z': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_int_value(args[i].z ? 1 : 0); break;
            case 'B': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_int_value((jint)args[i].b); break;
            case 'S': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_int_value((jint)args[i].s); break;
            case 'C': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_int_value((jint)args[i].c); break;
            case 'I': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_int_value(args[i].i); break;
            case 'J': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_long_value(args[i].j); break;
            case 'F': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_float_value(args[i].f); break;
            case 'D': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = js_vm_double_value(args[i].d); break;
            case '[':
            case 'L': locals[js_vm_local_perm(slot++, local_cap, local_perm_mul, local_perm_add)] = args[i].l ? js_vm_object_value(args[i].l) : js_vm_null_value(); break;
            default: return 0;
        }
    }
    return !(*env)->ExceptionCheck(env);
}

static int js_vm_invoke_method(JNIEnv *env, js_vm_program *p, int cp_idx, int opcode, js_vm_value *stack, int stack_cap, int *sp, js_vm_value *locals, int local_cap, uint32_t local_perm_mul, uint32_t local_perm_add) {
    int cp_self_call = 0;
    char *debug_ref = NULL;
    js_vm_last_failure_detail[0] = 0;
    jvalue *args = NULL;
    int argc = 0;
    jclass cls = NULL;
    jmethodID mid = NULL;
    int symbol_kind = 0;
    js_vm_symbol_cache_entry *cached_symbol = NULL;
    jobject target = NULL;
    js_vm_value target_value = js_vm_null_value();
    char ret_tag;
    jvalue result;
    int ok = 1;
    int is_constructor = 0;
    int nested_invoked = 0;
    int nested_result = 0;
    (void)argc;
    memset(&result, 0, sizeof(result));
    symbol_kind = (opcode == JS_VM_INVOKESTATIC) ? 4 : 5;
    debug_ref = js_vm_cp_string_owned(p, cp_idx);
    cached_symbol = js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind);
    if (!cached_symbol) {
        if (!js_vm_resolve_method_symbol(env, p, cp_idx, symbol_kind, opcode)) {
            snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "resolve opcode=%d cp=%d ref=%s", opcode, cp_idx, debug_ref ? debug_ref : "?");
            if (debug_ref) { js_vbc4_wipe_volatile(debug_ref, strlen(debug_ref)); free(debug_ref); }
            return 0;
        }
        cached_symbol = js_vm_symbol_cache_lookup(p, cp_idx, symbol_kind);
    }
    if (!cached_symbol || !cached_symbol->cls || !cached_symbol->arg_tags) {
        snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "cache opcode=%d cp=%d ref=%s", opcode, cp_idx, debug_ref ? debug_ref : "?");
        if (debug_ref) { js_vbc4_wipe_volatile(debug_ref, strlen(debug_ref)); free(debug_ref); }
        return 0;
    }
    if (opcode == JS_VM_INVOKESTATIC && p && p->original_owner && p->original_name && p->original_desc) {
        char *raw_ref = js_vm_cp_string_owned(p, cp_idx);
        js_vm_method_ref raw_mr;
        memset(&raw_mr, 0, sizeof(raw_mr));
        if (raw_ref && js_vm_parse_method_ref(raw_ref, &raw_mr)) {
            cp_self_call = strcmp(raw_mr.owner, p->original_owner) == 0 && strcmp(raw_mr.name, p->original_name) == 0 && strcmp(raw_mr.desc, p->original_desc) == 0;
            js_vm_free_method_ref(&raw_mr);
        }
        if (raw_ref) { js_vbc4_wipe_volatile(raw_ref, strlen(raw_ref)); free(raw_ref); }
    }
    cls = cached_symbol->cls;
    mid = cached_symbol->mid;
    is_constructor = cached_symbol->is_constructor != 0;
    if (opcode != JS_VM_INVOKESTATIC && cached_symbol->is_array_clone) {
        js_vm_value array_target;
        if (!js_vm_pop(stack, sp, &array_target)) return 0;
        if (array_target.type != JS_VM_VAL_OBJECT || !array_target.o) return js_vm_throw_new(env, "java/lang/NullPointerException", "array clone on null");
        if (!js_vm_is_array_object(env, array_target.o)) return 0;
        jobject clone = js_vm_clone_array(env, array_target.o);
        ok = !(*env)->ExceptionCheck(env) && clone && js_vm_push(stack, stack_cap, sp, js_vm_object_value(clone));
        return ok;
    }
    if (!js_vm_pop_jni_args_cached(env, stack, sp, cached_symbol->arg_tags, cached_symbol->argc, &args)) {
        snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "args opcode=%d cp=%d argc=%d sp=%d ref=%s", opcode, cp_idx, cached_symbol->argc, sp ? *sp : -1, debug_ref ? debug_ref : "?");
        if (debug_ref) { js_vbc4_wipe_volatile(debug_ref, strlen(debug_ref)); free(debug_ref); }
        return 0;
    }
    argc = cached_symbol->argc;
    if (opcode != JS_VM_INVOKESTATIC) {
        if (!js_vm_pop(stack, sp, &target_value)) ok = 0;
        if (ok && target_value.type == JS_VM_VAL_NULL) ok = js_vm_throw_new(env, "java/lang/NullPointerException", "null receiver");
        if (ok && target_value.type == JS_VM_VAL_UNINIT && is_constructor) {
            target = NULL;
        } else if (ok && target_value.type == JS_VM_VAL_OBJECT) {
            target = target_value.o;
        } else if (ok) {
            ok = 0;
        }
    }
    ret_tag = cached_symbol->ret_tag ? (char)cached_symbol->ret_tag : 'V';
    if (ok && cp_self_call && cached_symbol->is_self_call && ret_tag == 'V' && !is_constructor) {
        jobject self_target = (opcode == JS_VM_INVOKESTATIC) ? NULL : target;
        ok = js_vm_rebind_self_call_locals(env, cached_symbol, self_target, args, locals, local_cap, local_perm_mul, local_perm_add);
        js_vm_clear_value(&target_value);
        free(args);
        return ok ? 2 : 0;
    }
    if (ok) {
        if (is_constructor) {
            if (target_value.type == JS_VM_VAL_UNINIT) {
                jclass alloc_cls = target_value.uninit_type ? js_vm_find_class_name(env, target_value.uninit_type) : cls;
                if ((*env)->ExceptionCheck(env) || !alloc_cls) ok = 0;
                else target = (*env)->AllocObject(env, alloc_cls);
                if ((*env)->ExceptionCheck(env) || !target) ok = 0;
                else {
                    (*env)->CallNonvirtualVoidMethodA(env, target, cls, mid, args);
                    if ((*env)->ExceptionCheck(env)) ok = 0;
                }
                if (ok) {
                    if (js_jni_cache.initialized && js_jni_cache.throwable_class && (*env)->IsInstanceOf(env, target, js_jni_cache.throwable_class)) js_vm_apply_guest_stack_trace(env, target);
                    js_vm_replace_uninit_refs(stack, *sp, locals, local_cap, target_value.uninit_id, target);
                }
            } else if (target) {
                (*env)->CallNonvirtualVoidMethodA(env, target, cls, mid, args);
                if ((*env)->ExceptionCheck(env)) ok = 0;
                else if (js_jni_cache.initialized && js_jni_cache.throwable_class && (*env)->IsInstanceOf(env, target, js_jni_cache.throwable_class)) js_vm_apply_guest_stack_trace(env, target);
            } else {
                ok = 0;
            }
        } else if (opcode == JS_VM_INVOKESTATIC) {
            nested_result = js_vm_try_invoke_preloaded_nested(env, cached_symbol, NULL, args, stack, stack_cap, sp);
            if (nested_result > 0) {
                nested_invoked = 1;
                goto js_vm_invoke_method_after_nested_call;
            }
            if (nested_result < 0) { snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "static nested failed cp=%d", cp_idx); ok = 0; goto js_vm_invoke_method_after_nested_call; }
            if (!mid) { snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "static no mid cp=%d", cp_idx); ok = 0; goto js_vm_invoke_method_after_nested_call; }
            switch (ret_tag) {
                case 'V': (*env)->CallStaticVoidMethodA(env, cls, mid, args); break;
                case 'Z': result.z = (*env)->CallStaticBooleanMethodA(env, cls, mid, args); break;
                case 'B': result.b = (*env)->CallStaticByteMethodA(env, cls, mid, args); break;
                case 'S': result.s = (*env)->CallStaticShortMethodA(env, cls, mid, args); break;
                case 'C': result.c = (*env)->CallStaticCharMethodA(env, cls, mid, args); break;
                case 'I': result.i = (*env)->CallStaticIntMethodA(env, cls, mid, args); break;
                case 'J': result.j = (*env)->CallStaticLongMethodA(env, cls, mid, args); break;
                case 'F': result.f = (*env)->CallStaticFloatMethodA(env, cls, mid, args); break;
                case 'D': result.d = (*env)->CallStaticDoubleMethodA(env, cls, mid, args); break;
                default: result.l = (*env)->CallStaticObjectMethodA(env, cls, mid, args); break;
            }
        } else {
            if (opcode == JS_VM_INVOKESPECIAL) {
                if (!mid) { snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "special no mid cp=%d", cp_idx); ok = 0; goto js_vm_invoke_method_after_nested_call; }
                switch (ret_tag) {
                    case 'V': (*env)->CallNonvirtualVoidMethodA(env, target, cls, mid, args); break;
                    case 'Z': result.z = (*env)->CallNonvirtualBooleanMethodA(env, target, cls, mid, args); break;
                    case 'B': result.b = (*env)->CallNonvirtualByteMethodA(env, target, cls, mid, args); break;
                    case 'S': result.s = (*env)->CallNonvirtualShortMethodA(env, target, cls, mid, args); break;
                    case 'C': result.c = (*env)->CallNonvirtualCharMethodA(env, target, cls, mid, args); break;
                    case 'I': result.i = (*env)->CallNonvirtualIntMethodA(env, target, cls, mid, args); break;
                    case 'J': result.j = (*env)->CallNonvirtualLongMethodA(env, target, cls, mid, args); break;
                    case 'F': result.f = (*env)->CallNonvirtualFloatMethodA(env, target, cls, mid, args); break;
                    case 'D': result.d = (*env)->CallNonvirtualDoubleMethodA(env, target, cls, mid, args); break;
                    default: result.l = (*env)->CallNonvirtualObjectMethodA(env, target, cls, mid, args); break;
                }
            } else {
                if (cached_symbol->is_class_loader_define_class && cached_symbol->argc == 4 && ret_tag == 'L') {
                    result.l = js_vm_define_class_from_args(env, target, args, argc);
                    if ((*env)->ExceptionCheck(env) || !result.l) ok = 0;
                    goto js_vm_invoke_method_after_call;
                }
                if (cached_symbol->is_class_resource_stream && cached_symbol->argc == 1 && ret_tag == 'L' && cached_symbol->arg_tags && cached_symbol->arg_tags[0] == 'L') {
                    result.l = js_vm_class_resource_as_stream(env, target, (jstring)args[0].l);
                    if ((*env)->ExceptionCheck(env) || !result.l) ok = 0;
                    goto js_vm_invoke_method_after_call;
                }
                if (cached_symbol->is_class_loader_load_class && cached_symbol->argc == 1 && ret_tag == 'L' && cached_symbol->arg_tags && cached_symbol->arg_tags[0] == 'L') {
                    result.l = js_vm_load_class_from_args(env, target, mid, args, argc);
                    if ((*env)->ExceptionCheck(env) || !result.l) ok = 0;
                    goto js_vm_invoke_method_after_call;
                }
                int nonvirtual_owner_call = cached_symbol->is_class_mirror != 0;
                if (nonvirtual_owner_call) {
                    switch (ret_tag) {
                        case 'V': (*env)->CallNonvirtualVoidMethodA(env, target, cls, mid, args); break;
                        case 'Z': result.z = (*env)->CallNonvirtualBooleanMethodA(env, target, cls, mid, args); break;
                        case 'B': result.b = (*env)->CallNonvirtualByteMethodA(env, target, cls, mid, args); break;
                        case 'S': result.s = (*env)->CallNonvirtualShortMethodA(env, target, cls, mid, args); break;
                        case 'C': result.c = (*env)->CallNonvirtualCharMethodA(env, target, cls, mid, args); break;
                        case 'I': result.i = (*env)->CallNonvirtualIntMethodA(env, target, cls, mid, args); break;
                        case 'J': result.j = (*env)->CallNonvirtualLongMethodA(env, target, cls, mid, args); break;
                        case 'F': result.f = (*env)->CallNonvirtualFloatMethodA(env, target, cls, mid, args); break;
                        case 'D': result.d = (*env)->CallNonvirtualDoubleMethodA(env, target, cls, mid, args); break;
                        default: result.l = (*env)->CallNonvirtualObjectMethodA(env, target, cls, mid, args); break;
                    }
                } else {
                    nested_result = js_vm_try_invoke_preloaded_nested(env, cached_symbol, target, args, stack, stack_cap, sp);
                    if (nested_result > 0) {
                        nested_invoked = 1;
                        goto js_vm_invoke_method_after_nested_call;
                    }
                    if (nested_result < 0) { snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "virtual nested failed cp=%d ref=%s", cp_idx, debug_ref ? debug_ref : "?"); ok = 0; goto js_vm_invoke_method_after_nested_call; }
                    if (!mid && target && debug_ref) {
                        js_vm_method_ref dyn_mr;
                        memset(&dyn_mr, 0, sizeof(dyn_mr));
                        if (js_vm_parse_method_ref(debug_ref, &dyn_mr)) {
                            jclass target_cls = (*env)->GetObjectClass(env, target);
                            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                            if (target_cls) {
                                const char *dyn_lookup = dyn_mr.name ? dyn_mr.name : "";
                                char *dyn_mapped = js_lookup_bound_method(env, dyn_mr.owner, dyn_mr.name, dyn_mr.desc);
                                if (dyn_mapped && dyn_mapped[0]) dyn_lookup = dyn_mapped;
                                mid = (*env)->GetMethodID(env, target_cls, dyn_lookup, dyn_mr.desc);
                                if (((*env)->ExceptionCheck(env) || !mid) && dyn_mapped && dyn_mapped[0] && strcmp(dyn_lookup, dyn_mr.name) != 0) {
                                    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                                    mid = (*env)->GetMethodID(env, target_cls, dyn_mr.name, dyn_mr.desc);
                                }
                                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                                free(dyn_mapped);
                                (*env)->DeleteLocalRef(env, target_cls);
                            }
                            js_vm_free_method_ref(&dyn_mr);
                        }
                    }
                    if (!mid) { snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "virtual no mid cp=%d ref=%s", cp_idx, debug_ref ? debug_ref : "?"); ok = 0; goto js_vm_invoke_method_after_nested_call; }
                    switch (ret_tag) {
                        case 'V': (*env)->CallVoidMethodA(env, target, mid, args); break;
                        case 'Z': result.z = (*env)->CallBooleanMethodA(env, target, mid, args); break;
                        case 'B': result.b = (*env)->CallByteMethodA(env, target, mid, args); break;
                        case 'S': result.s = (*env)->CallShortMethodA(env, target, mid, args); break;
                        case 'C': result.c = (*env)->CallCharMethodA(env, target, mid, args); break;
                        case 'I': result.i = (*env)->CallIntMethodA(env, target, mid, args); break;
                        case 'J': result.j = (*env)->CallLongMethodA(env, target, mid, args); break;
                        case 'F': result.f = (*env)->CallFloatMethodA(env, target, mid, args); break;
                        case 'D': result.d = (*env)->CallDoubleMethodA(env, target, mid, args); break;
                        default: result.l = (*env)->CallObjectMethodA(env, target, mid, args); break;
                    }
                }
            }
        }
js_vm_invoke_method_after_nested_call:
js_vm_invoke_method_after_call:
        if ((*env)->ExceptionCheck(env)) ok = 0;
    }
    if (ok && !is_constructor && !nested_invoked) ok = js_vm_push_call_result(env, stack, stack_cap, sp, ret_tag, result);
    js_vm_clear_value(&target_value);
    if (debug_ref) { js_vbc4_wipe_volatile(debug_ref, strlen(debug_ref)); free(debug_ref); }
    free(args);
    return ok;
}

static int js_vm_reg_known_super_opcode(jint opcode) {
    switch (opcode) {
        case JS_VM_SUPER_CONST:
        case JS_VM_SUPER_INT_ARITH:
        case JS_VM_SUPER_CMP_BRANCH:
        case JS_VM_SUPER_INVOKE:
            return 1;
        default:
            return 0;
    }
}

static int js_vm_reg_super_original_allowed(jint super_opcode, jint original_opcode) {
    switch (super_opcode) {
        case JS_VM_SUPER_CONST:
            return original_opcode == JS_VM_ICONST || original_opcode == JS_VM_BIPUSH || original_opcode == JS_VM_SIPUSH;
        case JS_VM_SUPER_INT_ARITH:
            return original_opcode == JS_VM_IADD || original_opcode == JS_VM_ISUB || original_opcode == JS_VM_IMUL ||
                   original_opcode == JS_VM_IAND || original_opcode == JS_VM_IOR || original_opcode == JS_VM_IXOR ||
                   original_opcode == JS_VM_ISHL || original_opcode == JS_VM_ISHR || original_opcode == JS_VM_IUSHR;
        case JS_VM_SUPER_CMP_BRANCH:
            return original_opcode == JS_VM_IFEQ || original_opcode == JS_VM_IFNE || original_opcode == JS_VM_IF_ICMPEQ || original_opcode == JS_VM_IF_ICMPNE;
        case JS_VM_SUPER_INVOKE:
            return original_opcode == JS_VM_INVOKESTATIC || original_opcode == JS_VM_INVOKEVIRTUAL || original_opcode == JS_VM_INVOKESPECIAL || original_opcode == JS_VM_INVOKEINTERFACE;
        default:
            return 0;
    }
}

/* Item #7: a folded super-operator fuses `const, <binop>` where <binop> ranges over the
 * arithmetic, bitwise, and shift integer families. Expansion reproduces the two base ops
 * exactly, so semantics are preserved while many idioms collapse into one handler. */
static int js_vm_folded_fusion_second_allowed(jint canonical_second) {
    switch (canonical_second) {
        case JS_VM_IADD: case JS_VM_ISUB: case JS_VM_IMUL:
        case JS_VM_IAND: case JS_VM_IOR: case JS_VM_IXOR:
        case JS_VM_ISHL: case JS_VM_ISHR: case JS_VM_IUSHR:
            return 1;
        default:
            return 0;
    }
}

static int js_vm_reg_folded_super_allowed(const js_vm_reg_insn *insn) {
    if (!insn) return 0;
    jint first_opcode = js_vm_canonical_opcode(insn->srcA);
    jint second_opcode = js_vm_canonical_opcode(insn->srcB);
    if (insn->opcode == JS_VM_SUPER_INT_ARITH) {
        return (first_opcode == JS_VM_ICONST || first_opcode == JS_VM_BIPUSH || first_opcode == JS_VM_SIPUSH) &&
               js_vm_folded_fusion_second_allowed(second_opcode);
    }
    if (insn->opcode == JS_VM_SUPER_CMP_BRANCH) {
        return js_vm_folded_compare_builder_allowed(first_opcode) && js_vm_folded_predicate_branch_allowed(second_opcode);
    }
    return 0;
}

static int js_vm_validate_register_program(js_vm_program *p) {
    js_vm_last_validation_error = 0;
    if (!p || !p->reg_program.insns || p->reg_program.insn_count <= 0) { js_vm_last_validation_error = 101; return 0; }
    if (p->reg_program.register_count <= 0) { js_vm_last_validation_error = 102; return 0; }
    uint32_t digest = 0;
    int executable_seen = 0;
    int meta_seen = 0;
    int super_count = 0;
    for (int i = 0; i < p->reg_program.insn_count; i++) {
        js_vm_reg_insn *insn = &p->reg_program.insns[i];
        jint flags = insn->flags;
        if ((flags & ~(JS_VM_REG_FLAG_EXECUTABLE | JS_VM_REG_FLAG_SUPER | JS_VM_REG_FLAG_FOLDED | JS_VM_REG_FLAG_CONTINUATION)) != 0) { js_vm_last_validation_error = 110; return 0; }
        digest = js_vm_reg_fold_step(digest, insn);
        if ((flags & JS_VM_REG_FLAG_CONTINUATION) != 0) {
            if ((flags & ~JS_VM_REG_FLAG_CONTINUATION) != 0) { js_vm_last_validation_error = 111; return 0; }
            if (insn->opcode != JS_VM_REG_OPERAND_CONT || insn->canonical_opcode != JS_VM_REG_OPERAND_CONT || insn->original_opcode != JS_VM_REG_OPERAND_CONT) { js_vm_last_validation_error = 112; return 0; }
            continue;
        }
        if ((flags & JS_VM_REG_FLAG_EXECUTABLE) == 0) { js_vm_last_validation_error = 113; return 0; }
        if (insn->canonical_opcode == JS_VM_REG_META) {
            if (insn->opcode != JS_VM_REG_META || insn->operand < 0 || insn->operand >= p->cp_count || insn->operand != p->metadata_cp_index) { js_vm_last_validation_error = 114; return 0; }
            meta_seen = 1;
            continue;
        }
        executable_seen = 1;
        if ((flags & JS_VM_REG_FLAG_FOLDED) != 0 && (flags & JS_VM_REG_FLAG_SUPER) == 0) { js_vm_last_validation_error = 115; return 0; }
        if ((flags & JS_VM_REG_FLAG_SUPER) != 0) {
            super_count++;
            if (!js_vm_reg_known_super_opcode(insn->opcode) || insn->canonical_opcode != insn->opcode) {
                js_vm_last_validation_error = 116;
                return 0;
            }
            if ((flags & JS_VM_REG_FLAG_FOLDED) != 0) {
                if (!js_vm_reg_folded_super_allowed(insn)) { js_vm_last_validation_error = 117; return 0; }
            } else {
                if (insn->original_opcode != js_vm_canonical_opcode(insn->srcB)) { js_vm_last_validation_error = 118; return 0; }
                if (!js_vm_reg_super_original_allowed(insn->opcode, insn->original_opcode)) { js_vm_last_validation_error = 119; return 0; }
            }
        } else if (insn->opcode >= JS_VM_SUPER_BASE && insn->opcode <= JS_VM_SUPER_INVOKE) {
            js_vm_last_validation_error = 120;
            return 0;
        }
    }
    if (!executable_seen || !meta_seen) { js_vm_last_validation_error = 121; return 0; }
    if (digest != p->reg_program.fold_digest) { js_vm_last_validation_error = 122; return 0; }
    if (super_count != p->reg_program.super_count) { js_vm_last_validation_error = 123; return 0; }
    return 1;
}

JS_HIDDEN int js_vm_build_execution_program_from_registers(js_vm_program *source, js_vm_program *execution) {
    if (!source || !execution) return 0;
    if (!js_vm_validate_register_program(source)) return 0;
    js_vm_copy_execution_program_header(execution, source);
    for (int i = 0; i < source->reg_program.insn_count; i++) {
        js_vm_reg_insn *insn = &source->reg_program.insns[i];
        if ((insn->flags & JS_VM_REG_FLAG_CONTINUATION) != 0) return 0;
        if (insn->canonical_opcode == JS_VM_REG_META) continue;
        if ((insn->flags & JS_VM_REG_FLAG_FOLDED) != 0) {
            if (!js_vm_append_folded_super_insn(execution, insn->srcA, insn->srcB, insn->operand)) return 0;
            continue;
        }
        jint opcode = ((insn->flags & JS_VM_REG_FLAG_SUPER) != 0) ? insn->original_opcode : js_vm_canonical_opcode(insn->opcode);
        jint op_count = insn->dst;
        if (op_count < 0) return 0;
        jint inline_operands[16];
        jint *operands = op_count <= (jint)(sizeof(inline_operands) / sizeof(inline_operands[0])) ? inline_operands : (jint*)calloc((size_t)op_count, sizeof(jint));
        int operands_heap = operands != inline_operands;
        int ok = operands != NULL;
        if (ok && op_count > 0) {
            operands[0] = insn->operand;
            for (int extra = 1; extra < op_count; extra++) {
                if (++i >= source->reg_program.insn_count) { ok = 0; break; }
                js_vm_reg_insn *cont = &source->reg_program.insns[i];
                if ((cont->flags & JS_VM_REG_FLAG_CONTINUATION) == 0 || (cont->flags & ~JS_VM_REG_FLAG_CONTINUATION) != 0) { ok = 0; break; }
                if (cont->opcode != JS_VM_REG_OPERAND_CONT || cont->dst != extra || cont->srcA != insn->srcA) { ok = 0; break; }
                operands[extra] = cont->operand;
            }
        }
        if (ok) ok = js_vm_append_execution_insn(execution, opcode, op_count, operands);
        if (operands) js_vbc4_wipe_volatile(operands, (size_t)op_count * sizeof(jint));
        if (operands_heap) free(operands);
        if (!ok) return 0;
    }
    return execution->insn_count > 0 && execution->insns != NULL;
}

JS_HIDDEN int js_vm_execute(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret) {
    int local_cap = p->max_locals > 0 ? p->max_locals : 1;
    int stack_cap = p->max_stack + 4 > 8 ? p->max_stack + 4 : 8;
    js_vm_value inline_locals[32];
    js_vm_value inline_stack[64];
    js_vm_value *locals = local_cap <= (int)(sizeof(inline_locals) / sizeof(inline_locals[0])) ? inline_locals : (js_vm_value*)calloc((size_t)local_cap, sizeof(js_vm_value));
    js_vm_value *stack = stack_cap <= (int)(sizeof(inline_stack) / sizeof(inline_stack[0])) ? inline_stack : (js_vm_value*)calloc((size_t)stack_cap, sizeof(js_vm_value));
    int locals_heap = locals != inline_locals;
    int stack_heap = stack != inline_stack;
    int sp = 0;
    int pc = 0;
    int returned = 0;
    int ok = 1;
    int uninit_seq = 1;
    if (!locals || !stack) { if (locals_heap) free(locals); if (stack_heap) free(stack); return 0; }
    memset(locals, 0, sizeof(js_vm_value) * (size_t)local_cap);
    memset(stack, 0, sizeof(js_vm_value) * (size_t)stack_cap);
    for (int i = 0; i < local_cap; i++) locals[i] = js_vm_null_value();
    /* Derive per-run locals permutation parameters from a CSPRNG-backed nonce mix.
     * mul is made odd and combined with the program nonce so it is coprime to powers
     * of two; for non-power-of-two cap we additionally search a small window for a
     * value coprime to cap to guarantee bijectivity. */
    uint32_t local_perm_mul = 0;
    uint32_t local_perm_add = 0;
    {
        uint32_t mix = (uint32_t)js_vm_load_resident_build_seed(p);
        for (int i = 0; i < 16; i++) mix = (mix << 5) ^ (mix >> 27) ^ (uint32_t)p->nonce[i];
        mix ^= mix >> 16; mix *= 0x7FEB352Du; mix ^= mix >> 15; mix *= 0x846CA68Bu; mix ^= mix >> 16;
        local_perm_add = mix;
        uint32_t m = (mix ^ 0x9E3779B9u) | 1u; /* odd */
        int coprime = (local_cap <= 1);
        if (local_cap > 1) {
            int guard = 0;
            while (guard++ < 128) {
                uint32_t a = m % (uint32_t)local_cap;
                uint32_t b = (uint32_t)local_cap;
                while (b) { uint32_t t = a % b; a = b; b = t; }
                if (a == 1u) { coprime = 1; break; } /* gcd(m,cap)==1 -> bijection */
                m += 2u;
            }
        }
        /* Correctness guard: if no coprime multiplier was found, fall back to the
         * identity permutation (mul=1, add=0) so the locals mapping stays a bijection. */
        if (!coprime) { m = 1u; local_perm_add = 0u; }
        local_perm_mul = m;
    }
    if (args) {
        jsize argc = (*env)->GetArrayLength(env, args);
        /* The dispatch stub boxes one Object[] element per logical argument (plus a
         * leading `this` for instance methods), but the VBC4 body addresses locals by
         * JVM slot, where long/double parameters occupy two slots. Map each boxed
         * element to its JVM slot using the original descriptor so that arguments after
         * a long/double land in the correct local; a dense i->locals[i] mapping shifts
         * every later argument and surfaces as a null receiver / wrong value at runtime. */
        char *arg_tags = NULL;
        int desc_argc = 0;
        int is_static = (p->original_access & 0x0008) != 0;
        int have_desc = p->original_desc && js_vm_descriptor_arg_tags(p->original_desc, &arg_tags, &desc_argc);
        int slot = 0;
        for (jsize i = 0; i < argc; i++) {
            int width = 1;
            char tag = 0;
            int is_param = 1;
            if (have_desc) {
                int desc_index = is_static ? (int)i : (int)i - 1;
                if (!is_static && i == 0) {
                    is_param = 0; /* implicit `this` */
                } else if (desc_index >= 0 && desc_index < desc_argc) {
                    tag = arg_tags[desc_index];
                    if (tag == 'J' || tag == 'D') width = 2;
                }
            }
            if (slot >= local_cap) break;
            jobject arg = (*env)->GetObjectArrayElement(env, args, i);
            js_vm_value *dst = &locals[js_vm_local_perm(slot, local_cap, local_perm_mul, local_perm_add)];
            /* The dispatch stub boxes primitive arguments (and passes objects directly).
             * Unbox only when the *declared* parameter type is primitive; reference-typed
             * parameters (and `this`) must keep their object identity, otherwise a Number/
             * Integer/Long argument would be collapsed to a raw VM primitive and any later
             * virtual call on it (e.g. Number.longValue()) fails with a null/!object
             * receiver. When the descriptor is unavailable, fall back to the historical
             * auto-unbox behavior. */
            int keep_object = have_desc && (!is_param || tag == 'L' || tag == '[');
            if (keep_object) {
                *dst = js_vm_object_value(arg);
                ok = 1;
            } else {
                ok = js_vm_boxed_arg(env, arg, dst);
            }
            if (!ok) break;
            slot += width;
        }
        if (arg_tags) free(arg_tags);
    }
    *ret = js_vm_null_value();
    int dispatch_step = 0;
    uint32_t vm_trace_state = 0;  /* accumulates anti-trace detection state */
    uint32_t vm_dispatch_drift_state = js_vm_dispatch_drift_step(p, js_vm_shared_dispatch_seed_for(p), 0, pc, sp);  /* self-modifying dispatch salt state, seeded from shared cross-method pool (item #6) */
    int execution_step_limit = (p->insn_count > 0 ? p->insn_count : 1) * 250000;
    if (execution_step_limit < 1000000) execution_step_limit = 1000000;
    uint32_t saved_trace_poison_seed = js_vm_trace_poison_seed;
    js_vm_trace_poison_seed = 0;  /* reset CP poison for this execution frame only */
    while (ok && !returned && pc >= 0 && pc < p->insn_count) {
        if (dispatch_step >= execution_step_limit) {
            js_vm_last_failure_pc = pc;
            js_vm_last_failure_opcode = JS_VM_UNSUPPORTED;
            js_vm_last_failure_sp = sp;
            js_vm_last_failure_step = dispatch_step;
            js_vm_last_failure_step_limit = execution_step_limit;
            js_vm_last_failure_insn_count = p->insn_count;
            js_vm_last_failure_step = dispatch_step;
            js_vm_last_failure_step_limit = execution_step_limit;
            js_vm_last_failure_cached = p->cached_execution_ready;
            ok = 0;
            break;
        }
        js_vm_dispatch_fetch:
        /* Anti-trace trap: detect debugger/trace attachment */
        if (js_vm_anti_trace_check(dispatch_step, &vm_trace_state)) {
            /* Poison the dispatch: corrupt the next opcode to land on a wrong handler.
             * This makes single-step traces produce garbage instruction sequences. */
            p->insns[pc >= 0 && pc < p->insn_count ? pc : 0].opcode ^= (jint)(vm_trace_state & 0xFFu);
        }
        int fault_pc = pc;
        jobject pending_throw = NULL;
        js_vm_insn active_insn = p->insns[pc];
        jint active_raw_opcode = p->insns[pc].opcode;
        jint active_mask = js_vm_resident_opcode_mask(p, pc);
        jint active_epoch = p->insns[pc].opcode_epoch;
        active_insn.opcode = js_vm_canonical_opcode(active_raw_opcode ^ active_mask);
        pc++;
        if (js_vm_dispatch_rotation_due(p, vm_dispatch_drift_state, dispatch_step, fault_pc, sp)) {
            vm_dispatch_drift_state = js_vm_dispatch_drift_step(p, vm_dispatch_drift_state, dispatch_step, fault_pc, sp);
            js_vm_rotate_resident_block(p, fault_pc, dispatch_step, vm_dispatch_drift_state, pc, sp);
        }
        js_vm_rewrap_resident_opcode(p, fault_pc, active_insn.opcode, dispatch_step++, pc, sp);
        js_vm_insn *insn = &active_insn;
        jint inline_ops[16];
        jint *decoded_ops = NULL;
        int decoded_ops_heap = 0;
        if (active_insn.op_count > 0) {
            decoded_ops = active_insn.op_count <= (jint)(sizeof(inline_ops) / sizeof(inline_ops[0])) ? inline_ops : (jint*)calloc((size_t)active_insn.op_count, sizeof(jint));
            decoded_ops_heap = decoded_ops != inline_ops;
            if (!decoded_ops) {
                active_insn.opcode = JS_VM_UNSUPPORTED;
                active_insn.op_count = 0;
            } else {
                int resident_index = pc - 1;
                for (int operand_index = 0; operand_index < active_insn.op_count; operand_index++) {
                    decoded_ops[operand_index] = js_vm_load_resident_operand(p, resident_index, operand_index);
                }
                active_insn.ops = decoded_ops;
            }
        } else {
            active_insn.ops = NULL;
        }
        jint *ops = insn->ops;
        js_vm_value a = js_vm_null_value();
        js_vm_value b = js_vm_null_value();
        js_vm_value c = js_vm_null_value();
        js_vm_value d = js_vm_null_value();
        jobject synthetic_throw = NULL;
        jint ia = 0, ib = 0;
        jlong la = 0, lb = 0;
        jfloat fa = 0.0f, fb = 0.0f;
        jdouble da = 0.0, db = 0.0;
#define JS_VM_DISPATCH(insn_ptr) int js_vm_dispatch_opcode = (insn_ptr)->opcode; uint32_t js_vm_dispatch_salt_value = js_vm_poison_dispatch_salt(js_vm_dispatch_progress_salt(p, pc, vm_dispatch_drift_state), vm_trace_state); int js_vm_dispatch_matched = 0; if (0)
#define JS_VM_CASE(x) (void)0; } if (!js_vm_dispatch_matched && js_vm_case_match(js_vm_dispatch_opcode, (x), js_vm_dispatch_salt_value)) js_vm_dispatch_matched = 1; if (js_vm_dispatch_matched) {
#define JS_VM_BREAK do { js_vm_dispatch_matched = 0; goto js_vm_dispatch_done; } while (0)
#define JS_VM_DEFAULT (void)0; } if (!js_vm_dispatch_matched) {
        JS_VM_DISPATCH(insn) {
            JS_VM_CASE(JS_VM_NOP)
            JS_VM_CASE(JS_VM_MAXS)
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_UNSUPPORTED)
                ok = 0;
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ACONST_NULL)
                ok = js_vm_push(stack, stack_cap, &sp, js_vm_null_value());
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ICONST)
            JS_VM_CASE(JS_VM_BIPUSH)
            JS_VM_CASE(JS_VM_SIPUSH)
                ok = insn->op_count >= 1 && js_vm_push(stack, stack_cap, &sp, js_vm_int_value(ops[0]));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_FCONST)
                if (insn->op_count < 1) { ok = 0; JS_VM_BREAK; }
                { uint32_t bits = (uint32_t)ops[0]; jfloat fv; memcpy(&fv, &bits, sizeof(fv)); ok = js_vm_push(stack, stack_cap, &sp, js_vm_float_value(fv)); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LCONST)
            JS_VM_CASE(JS_VM_DCONST)
            JS_VM_CASE(JS_VM_LDC_INT)
            JS_VM_CASE(JS_VM_LDC_LONG)
            JS_VM_CASE(JS_VM_LDC_FLOAT)
            JS_VM_CASE(JS_VM_LDC_DOUBLE)
            JS_VM_CASE(JS_VM_LDC_STRING)
            JS_VM_CASE(JS_VM_LDC_TYPE)
            JS_VM_CASE(JS_VM_LDC_HANDLE)
                ok = insn->op_count >= 1 && js_vm_cp_value(env, p, args, ops[0], insn->opcode, &a) && js_vm_push(stack, stack_cap, &sp, a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ILOAD) JS_VM_CASE(JS_VM_LLOAD) JS_VM_CASE(JS_VM_FLOAD) JS_VM_CASE(JS_VM_DLOAD) JS_VM_CASE(JS_VM_ALOAD)
                ok = insn->op_count >= 1 && ops[0] >= 0 && ops[0] < local_cap && js_vm_push_copy(stack, stack_cap, &sp, locals[js_vm_local_perm(ops[0], local_cap, local_perm_mul, local_perm_add)]);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ISTORE) JS_VM_CASE(JS_VM_LSTORE) JS_VM_CASE(JS_VM_FSTORE) JS_VM_CASE(JS_VM_DSTORE) JS_VM_CASE(JS_VM_ASTORE)
                ok = insn->op_count >= 1 && ops[0] >= 0 && ops[0] < local_cap;
                if (ok) {
                    int local_index = js_vm_local_perm(ops[0], local_cap, local_perm_mul, local_perm_add);
                    ok = js_vm_pop(stack, &sp, &a);
                    if (ok) {
                        js_vm_clear_value(&locals[local_index]);
                        locals[local_index] = a;
                    }
                }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_RET)
                ok = insn->op_count >= 1 && ops[0] >= 0 && ops[0] < local_cap && js_vm_to_int(locals[js_vm_local_perm(ops[0], local_cap, local_perm_mul, local_perm_add)], &ia);
                if (ok) pc = ia;
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IINC)
                ok = insn->op_count >= 2 && ops[0] >= 0 && ops[0] < local_cap && js_vm_to_int(locals[js_vm_local_perm(ops[0], local_cap, local_perm_mul, local_perm_add)], &ia);
                if (ok) locals[js_vm_local_perm(ops[0], local_cap, local_perm_mul, local_perm_add)] = js_vm_int_value(ia + ops[1]);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_POP)
                ok = js_vm_pop(stack, &sp, &a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_POP2)
                ok = js_vm_pop(stack, &sp, &a);
                if (ok && !js_vm_value_is_wide(a)) ok = js_vm_pop(stack, &sp, &b);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DUP)
                ok = js_vm_stack_has_capacity(stack_cap, sp, 1) && js_vm_pop(stack, &sp, &a);
                if (ok) ok = js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, a);
                if (!ok) js_vm_clear_value(&a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DUP_X1)
                ok = js_vm_stack_has_capacity(stack_cap, sp, 1) && js_vm_pop(stack, &sp, &a) && js_vm_pop(stack, &sp, &b);
                if (ok) ok = js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                if (!ok) { js_vm_clear_value(&a); js_vm_clear_value(&b); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DUP_X2)
                ok = js_vm_stack_has_capacity(stack_cap, sp, 1) && js_vm_pop(stack, &sp, &a) && js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &c);
                if (ok) ok = js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, c) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                if (!ok) { js_vm_clear_value(&a); js_vm_clear_value(&b); js_vm_clear_value(&c); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DUP2)
                ok = js_vm_stack_has_capacity(stack_cap, sp, 2) && js_vm_pop(stack, &sp, &a);
                if (ok && js_vm_value_is_wide(a)) {
                    ok = js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, a);
                } else if (ok) {
                    ok = js_vm_pop(stack, &sp, &b) && js_vm_push_copy(stack, stack_cap, &sp, b) && js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                }
                if (!ok) { js_vm_clear_value(&a); js_vm_clear_value(&b); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DUP2_X1)
                ok = js_vm_stack_has_capacity(stack_cap, sp, 2) && js_vm_pop(stack, &sp, &a);
                if (ok && js_vm_value_is_wide(a)) {
                    ok = js_vm_pop(stack, &sp, &b) && !js_vm_value_is_wide(b) && js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                } else if (ok) {
                    ok = js_vm_pop(stack, &sp, &b) && !js_vm_value_is_wide(b) && js_vm_pop(stack, &sp, &c) && !js_vm_value_is_wide(c) && js_vm_push_copy(stack, stack_cap, &sp, b) && js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, c) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                }
                if (!ok) { js_vm_clear_value(&a); js_vm_clear_value(&b); js_vm_clear_value(&c); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DUP2_X2)
                ok = js_vm_stack_has_capacity(stack_cap, sp, 2) && js_vm_pop(stack, &sp, &a);
                if (ok && js_vm_value_is_wide(a)) {
                    ok = js_vm_pop(stack, &sp, &b);
                    if (ok && js_vm_value_is_wide(b)) {
                        ok = js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                    } else if (ok) {
                        ok = js_vm_pop(stack, &sp, &c) && !js_vm_value_is_wide(c) && js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, c) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                    }
                } else if (ok) {
                    ok = js_vm_pop(stack, &sp, &b) && !js_vm_value_is_wide(b) && js_vm_pop(stack, &sp, &c);
                    if (ok && js_vm_value_is_wide(c)) {
                        ok = js_vm_push_copy(stack, stack_cap, &sp, b) && js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, c) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                    } else if (ok) {
                        ok = js_vm_pop(stack, &sp, &d) && !js_vm_value_is_wide(d) && js_vm_push_copy(stack, stack_cap, &sp, b) && js_vm_push_copy(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, d) && js_vm_push(stack, stack_cap, &sp, c) && js_vm_push(stack, stack_cap, &sp, b) && js_vm_push(stack, stack_cap, &sp, a);
                    }
                }
                if (!ok) { js_vm_clear_value(&a); js_vm_clear_value(&b); js_vm_clear_value(&c); js_vm_clear_value(&d); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_SWAP)
                ok = js_vm_pop(stack, &sp, &a) && js_vm_pop(stack, &sp, &b) && js_vm_push(stack, stack_cap, &sp, a) && js_vm_push(stack, stack_cap, &sp, b);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IADD) JS_VM_CASE(JS_VM_ISUB) JS_VM_CASE(JS_VM_IMUL) JS_VM_CASE(JS_VM_IDIV) JS_VM_CASE(JS_VM_IREM)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_to_int(b, &ib);
                if (ok && (insn->opcode == JS_VM_IDIV || insn->opcode == JS_VM_IREM) && ib == 0) { synthetic_throw = js_vm_new_throwable(env, "java/lang/ArithmeticException", "/ by zero"); ok = 0; }
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(insn->opcode == JS_VM_IADD ? ia + ib : insn->opcode == JS_VM_ISUB ? ia - ib : insn->opcode == JS_VM_IMUL ? ia * ib : insn->opcode == JS_VM_IDIV ? ia / ib : ia % ib));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_INEG)
                ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value(-ia));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LADD) JS_VM_CASE(JS_VM_LSUB) JS_VM_CASE(JS_VM_LMUL) JS_VM_CASE(JS_VM_LDIV) JS_VM_CASE(JS_VM_LREM)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_to_long(b, &lb);
                if (ok && (insn->opcode == JS_VM_LDIV || insn->opcode == JS_VM_LREM) && lb == 0) { synthetic_throw = js_vm_new_throwable(env, "java/lang/ArithmeticException", "/ by zero"); ok = 0; }
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_long_value(insn->opcode == JS_VM_LADD ? la + lb : insn->opcode == JS_VM_LSUB ? la - lb : insn->opcode == JS_VM_LMUL ? la * lb : insn->opcode == JS_VM_LDIV ? la / lb : la % lb));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LNEG)
                ok = js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_push(stack, stack_cap, &sp, js_vm_long_value(-la));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_FADD) JS_VM_CASE(JS_VM_FSUB) JS_VM_CASE(JS_VM_FMUL) JS_VM_CASE(JS_VM_FDIV)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_to_float(b, &fb);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_float_value(insn->opcode == JS_VM_FADD ? fa + fb : insn->opcode == JS_VM_FSUB ? fa - fb : insn->opcode == JS_VM_FMUL ? fa * fb : fa / fb));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_FNEG)
                ok = js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_push(stack, stack_cap, &sp, js_vm_float_value(-fa));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_FREM)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_to_float(b, &fb);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_float_value(fmodf(fa, fb)));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DADD) JS_VM_CASE(JS_VM_DSUB) JS_VM_CASE(JS_VM_DMUL) JS_VM_CASE(JS_VM_DDIV)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_to_double(b, &db);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_double_value(insn->opcode == JS_VM_DADD ? da + db : insn->opcode == JS_VM_DSUB ? da - db : insn->opcode == JS_VM_DMUL ? da * db : da / db));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DNEG)
                ok = js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_push(stack, stack_cap, &sp, js_vm_double_value(-da));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DREM)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_to_double(b, &db);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_double_value(fmod(da, db)));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ISHL) JS_VM_CASE(JS_VM_ISHR) JS_VM_CASE(JS_VM_IUSHR)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_to_int(b, &ib);
                if (ok) { int sh = ib & 31; jint r = insn->opcode == JS_VM_ISHL ? (jint)(((uint32_t)ia) << sh) : insn->opcode == JS_VM_ISHR ? (jint)(ia >> sh) : (jint)(((uint32_t)ia) >> sh); ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(r)); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LSHL) JS_VM_CASE(JS_VM_LSHR) JS_VM_CASE(JS_VM_LUSHR)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_to_int(b, &ib);
                if (ok) { int sh = ib & 63; jlong r = insn->opcode == JS_VM_LSHL ? (jlong)(((uint64_t)la) << sh) : insn->opcode == JS_VM_LSHR ? (jlong)(la >> sh) : (jlong)(((uint64_t)la) >> sh); ok = js_vm_push(stack, stack_cap, &sp, js_vm_long_value(r)); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IAND) JS_VM_CASE(JS_VM_IOR) JS_VM_CASE(JS_VM_IXOR)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_to_int(b, &ib);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(insn->opcode == JS_VM_IAND ? ia & ib : insn->opcode == JS_VM_IOR ? ia | ib : ia ^ ib));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LAND) JS_VM_CASE(JS_VM_LOR) JS_VM_CASE(JS_VM_LXOR)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_to_long(b, &lb);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_long_value(insn->opcode == JS_VM_LAND ? la & lb : insn->opcode == JS_VM_LOR ? la | lb : la ^ lb));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_I2L) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_long_value((jlong)ia)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_I2F) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_float_value((jfloat)ia)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_I2D) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_double_value((jdouble)ia)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_L2I) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value((jint)la)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_L2F) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_push(stack, stack_cap, &sp, js_vm_float_value((jfloat)la)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_L2D) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_push(stack, stack_cap, &sp, js_vm_double_value((jdouble)la)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_F2I) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value((jint)fa)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_F2L) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_push(stack, stack_cap, &sp, js_vm_long_value((jlong)fa)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_F2D) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_push(stack, stack_cap, &sp, js_vm_double_value((jdouble)fa)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_D2I) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value((jint)da)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_D2L) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_push(stack, stack_cap, &sp, js_vm_long_value((jlong)da)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_D2F) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_push(stack, stack_cap, &sp, js_vm_float_value((jfloat)da)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_I2B) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value((jbyte)ia)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_I2C) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value((jint)(jchar)ia)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_I2S) ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_push(stack, stack_cap, &sp, js_vm_int_value((jshort)ia)); JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LCMP)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_long(a, &la) && js_vm_to_long(b, &lb);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(la == lb ? 0 : (la < lb ? -1 : 1)));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_FCMPL) JS_VM_CASE(JS_VM_FCMPG)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_float(a, &fa) && js_vm_to_float(b, &fb);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(fa == fb ? 0 : (fa < fb ? -1 : (fa > fb ? 1 : (insn->opcode == JS_VM_FCMPL ? -1 : 1)))));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_DCMPL) JS_VM_CASE(JS_VM_DCMPG)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_double(a, &da) && js_vm_to_double(b, &db);
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(da == db ? 0 : (da < db ? -1 : (da > db ? 1 : (insn->opcode == JS_VM_DCMPL ? -1 : 1)))));
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IFEQ) JS_VM_CASE(JS_VM_IFNE) JS_VM_CASE(JS_VM_IFLT) JS_VM_CASE(JS_VM_IFGE) JS_VM_CASE(JS_VM_IFGT) JS_VM_CASE(JS_VM_IFLE)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok && ((insn->opcode == JS_VM_IFEQ && ia == 0) || (insn->opcode == JS_VM_IFNE && ia != 0) || (insn->opcode == JS_VM_IFLT && ia < 0) || (insn->opcode == JS_VM_IFGE && ia >= 0) || (insn->opcode == JS_VM_IFGT && ia > 0) || (insn->opcode == JS_VM_IFLE && ia <= 0))) pc = ops[0];
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IF_ICMPEQ) JS_VM_CASE(JS_VM_IF_ICMPNE) JS_VM_CASE(JS_VM_IF_ICMPLT) JS_VM_CASE(JS_VM_IF_ICMPGE) JS_VM_CASE(JS_VM_IF_ICMPGT) JS_VM_CASE(JS_VM_IF_ICMPLE)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_to_int(b, &ib);
                if (ok && ((insn->opcode == JS_VM_IF_ICMPEQ && ia == ib) || (insn->opcode == JS_VM_IF_ICMPNE && ia != ib) || (insn->opcode == JS_VM_IF_ICMPLT && ia < ib) || (insn->opcode == JS_VM_IF_ICMPGE && ia >= ib) || (insn->opcode == JS_VM_IF_ICMPGT && ia > ib) || (insn->opcode == JS_VM_IF_ICMPLE && ia <= ib))) pc = ops[0];
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IF_ACMPEQ) JS_VM_CASE(JS_VM_IF_ACMPNE)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a);
                if (ok && a.type != JS_VM_VAL_OBJECT && a.type != JS_VM_VAL_NULL) ok = 0;
                if (ok && b.type != JS_VM_VAL_OBJECT && b.type != JS_VM_VAL_NULL) ok = 0;
                if (ok) { int eq = js_vm_value_is_null(a) && js_vm_value_is_null(b); if (!eq && !js_vm_value_is_null(a) && !js_vm_value_is_null(b)) eq = (*env)->IsSameObject(env, a.o, b.o); if ((insn->opcode == JS_VM_IF_ACMPEQ && eq) || (insn->opcode == JS_VM_IF_ACMPNE && !eq)) pc = ops[0]; }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_GOTO)
                ok = insn->op_count >= 1;
                if (ok) pc = ops[0];
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_JSR)
                ok = insn->op_count >= 1 && js_vm_push(stack, stack_cap, &sp, js_vm_int_value(pc));
                if (ok) pc = ops[0];
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IFNULL) JS_VM_CASE(JS_VM_IFNONNULL)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a);
                if (ok) { int is_null = js_vm_value_is_null(a); if ((insn->opcode == JS_VM_IFNULL && is_null) || (insn->opcode == JS_VM_IFNONNULL && !is_null)) pc = ops[0]; }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IRETURN) JS_VM_CASE(JS_VM_LRETURN) JS_VM_CASE(JS_VM_FRETURN) JS_VM_CASE(JS_VM_DRETURN) JS_VM_CASE(JS_VM_ARETURN)
                ok = js_vm_pop(stack, &sp, ret);
                returned = ok;
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_RETURN)
                *ret = js_vm_null_value();
                returned = 1;
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ATHROW)
                ok = js_vm_pop(stack, &sp, &a);
                if (ok) { pending_throw = js_vm_throwable_from_value(env, a); if ((*env)->ExceptionCheck(env)) { pending_throw = (*env)->ExceptionOccurred(env); (*env)->ExceptionClear(env); } }
                if (!pending_throw) ok = 0;
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_GETSTATIC)
            JS_VM_CASE(JS_VM_PUTSTATIC)
            JS_VM_CASE(JS_VM_GETFIELD)
            JS_VM_CASE(JS_VM_PUTFIELD)
                ok = insn->op_count >= 1 && js_vm_field_access(env, p, ops[0], insn->opcode, stack, stack_cap, &sp);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_INVOKESTATIC)
            JS_VM_CASE(JS_VM_INVOKEVIRTUAL)
            JS_VM_CASE(JS_VM_INVOKESPECIAL)
            JS_VM_CASE(JS_VM_INVOKEINTERFACE)
                if (insn->op_count >= 1) {
                    int invoke_status = js_vm_invoke_method(env, p, ops[0], insn->opcode, stack, stack_cap, &sp, locals, local_cap, local_perm_mul, local_perm_add);
                    if (invoke_status == 2) {
                        sp = 0;
                        pc = 0;
                        ok = 1;
                    } else {
                        ok = invoke_status != 0;
                    }
                } else {
                    ok = 0;
                }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_INVOKEDYNAMIC)
                ok = insn->op_count >= 1 && js_vm_invoke_dynamic(env, p, ops[0], stack, stack_cap, &sp);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_NEW)
                ok = insn->op_count >= 1;
                if (ok) { char *type = js_vm_cp_string_owned(p, ops[0]); ok = type && js_vm_push(stack, stack_cap, &sp, js_vm_uninit_value(uninit_seq++, type)); if (!ok && type) { js_vbc4_wipe_volatile(type, strlen(type)); free(type); } }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_NEWARRAY)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok) { jobject arr = js_vm_new_primitive_array(env, ops[0], ia); ok = !(*env)->ExceptionCheck(env) && arr && js_vm_push(stack, stack_cap, &sp, js_vm_object_value(arr)); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ANEWARRAY)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok) { js_vm_symbol_cache_entry *cached_cls = js_vm_get_cached_class_symbol(env, p, ops[0], 6); jclass component = cached_cls ? cached_cls->cls : NULL; jobject arr = ((*env)->ExceptionCheck(env) || !component) ? NULL : (jobject)(*env)->NewObjectArray(env, ia, component, NULL); ok = !(*env)->ExceptionCheck(env) && arr && js_vm_push(stack, stack_cap, &sp, js_vm_object_value(arr)); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_ARRAYLENGTH)
                ok = js_vm_pop(stack, &sp, &a);
                if (ok) { jobject arr = NULL; ok = js_vm_to_object(a, &arr); if (ok && !arr) ok = js_vm_throw_new(env, "java/lang/NullPointerException", "arraylength on null"); if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value((*env)->GetArrayLength(env, (jarray)arr))); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_CHECKCAST)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a);
                if (ok && !js_vm_value_is_null(a)) { jobject obj = NULL; js_vm_symbol_cache_entry *cached_cls = js_vm_get_cached_class_symbol(env, p, ops[0], 6); jclass cls = cached_cls ? cached_cls->cls : NULL; ok = js_vm_to_object(a, &obj) && !(*env)->ExceptionCheck(env) && cls; if (ok && !(*env)->IsInstanceOf(env, obj, cls)) ok = js_vm_throw_new(env, "java/lang/ClassCastException", cached_cls && cached_cls->type_name ? cached_cls->type_name : "type"); }
                if (ok) ok = js_vm_push(stack, stack_cap, &sp, a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_INSTANCEOF)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a);
                if (ok) { jobject obj = NULL; js_vm_symbol_cache_entry *cached_cls = js_vm_get_cached_class_symbol(env, p, ops[0], 6); jclass cls = cached_cls ? cached_cls->cls : NULL; int result = 0; ok = js_vm_to_object(a, &obj) && !(*env)->ExceptionCheck(env) && cls; if (ok && obj) result = (*env)->IsInstanceOf(env, obj, cls); if (ok) ok = js_vm_push(stack, stack_cap, &sp, js_vm_int_value(result ? 1 : 0)); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_MULTIANEWARRAY)
                ok = insn->op_count >= 2 && ops[1] > 0;
                if (ok) { int dims_count = ops[1]; jint *dims = (jint*)calloc((size_t)dims_count, sizeof(jint)); if (!dims) { ok = 0; JS_VM_BREAK; } for (int i = dims_count - 1; i >= 0; i--) { ok = js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &dims[i]); if (!ok) break; } if (ok) { char *desc = js_vm_cp_string_owned(p, ops[0]); jobject arr = desc ? js_vm_new_multi_array(env, desc, dims, dims_count) : NULL; if (desc) { js_vbc4_wipe_volatile(desc, strlen(desc)); free(desc); } ok = !(*env)->ExceptionCheck(env) && arr && js_vm_push(stack, stack_cap, &sp, js_vm_object_value(arr)); } free(dims); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IALOAD) JS_VM_CASE(JS_VM_LALOAD) JS_VM_CASE(JS_VM_FALOAD) JS_VM_CASE(JS_VM_DALOAD) JS_VM_CASE(JS_VM_AALOAD) JS_VM_CASE(JS_VM_BALOAD) JS_VM_CASE(JS_VM_CALOAD) JS_VM_CASE(JS_VM_SALOAD)
                ok = js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(b, &ia);
                if (ok) { js_vm_value value; ok = js_vm_array_load(env, insn->opcode, a, ia, &value) && js_vm_push(stack, stack_cap, &sp, value); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IASTORE) JS_VM_CASE(JS_VM_LASTORE) JS_VM_CASE(JS_VM_FASTORE) JS_VM_CASE(JS_VM_DASTORE) JS_VM_CASE(JS_VM_AASTORE) JS_VM_CASE(JS_VM_BASTORE) JS_VM_CASE(JS_VM_CASTORE) JS_VM_CASE(JS_VM_SASTORE)
                ok = js_vm_pop(stack, &sp, &c) && js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(b, &ia);
                if (ok) ok = js_vm_array_store(env, insn->opcode, a, ia, c);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_MONITORENTER)
            JS_VM_CASE(JS_VM_MONITOREXIT)
                ok = js_vm_pop(stack, &sp, &a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_TABLESWITCH)
                ok = insn->op_count >= 3 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok) { int min = ops[0], max = ops[1]; pc = (ia < min || ia > max) ? ops[2] : ops[3 + (ia - min)]; }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LOOKUPSWITCH)
                ok = insn->op_count >= 2 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok) { int npairs = ops[0]; int target = ops[1]; if (insn->op_count < 2 + npairs * 2) { ok = 0; JS_VM_BREAK; } for (int i = 0; i < npairs; i++) if (ops[2 + i * 2] == ia) { target = ops[3 + i * 2]; break; } pc = target; }
                JS_VM_BREAK;
            JS_VM_DEFAULT
                ok = 0;
                JS_VM_BREAK;
        }
        js_vm_dispatch_done:
        if (!ok) {
            js_vm_last_failure_pc = fault_pc;
            js_vm_last_failure_opcode = active_insn.opcode;
            js_vm_last_failure_sp = sp;
            js_vm_last_failure_raw_opcode = active_raw_opcode;
            js_vm_last_failure_mask = active_mask;
            js_vm_last_failure_epoch = active_epoch;
            js_vm_last_failure_cached = p->cached_execution_ready;
            js_vm_last_failure_insn_count = p->insn_count;
        }
        if (decoded_ops) {
            js_vbc4_wipe_volatile(decoded_ops, (size_t)active_insn.op_count * sizeof(jint));
            if (decoded_ops_heap) free(decoded_ops);
            decoded_ops = NULL;
        }
        if (synthetic_throw && js_vm_handle_exception(env, p, stack, stack_cap, &sp, &pc, synthetic_throw, fault_pc)) {
            ok = 1;
            goto js_vm_dispatch_fetch;
        }
        if (synthetic_throw) {
            (*env)->Throw(env, (jthrowable)synthetic_throw);
            ok = 0;
        }
        if (pending_throw || (*env)->ExceptionCheck(env)) {
            jthrowable thrown = NULL;
            if (pending_throw) {
                thrown = (jthrowable)pending_throw;
            } else {
                thrown = (*env)->ExceptionOccurred(env);
                (*env)->ExceptionClear(env);
            }
            if (thrown && js_vm_handle_exception(env, p, stack, stack_cap, &sp, &pc, thrown, fault_pc)) {
                ok = 1;
                goto js_vm_dispatch_fetch;
            }
            if (thrown) (*env)->Throw(env, thrown);
            ok = 0;
        }
    }
    if (ok && !returned) *ret = js_vm_null_value();
    if (ret_desc != 'V' && ok && !returned) ok = 0;
    js_vm_clear_value_range(locals, local_cap);
    js_vm_clear_value_range(stack, stack_cap);
    if (locals_heap) free(locals);
    if (stack_heap) free(stack);
    /* Item #6: evolve the shared cross-method dispatcher pool so subsequent virtualized
     * methods observe state produced by this one (interprocedural slice scheduling). */
    js_vm_shared_dispatch_evolve(p, vm_dispatch_drift_state, dispatch_step);
    js_vm_trace_poison_seed = saved_trace_poison_seed;
    return ok;
}

JS_LOCAL jobject JNICALL
jsn_r20(
    JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args)
{
    if ((*env)->PushLocalFrame(env, 4096) != 0) {
        return js_vm_fail_closed(env, "native VM local frame allocation failed");
    }
    jobject result = js_vm_execute_resource(env, cls, entryToken, resourcePath, args);
    return (*env)->PopLocalFrame(env, result);
}
JS_LOCAL void JNICALL
jsn_r23(JNIEnv *env, jclass cls, jlong entryToken)
{
    if ((*env)->PushLocalFrame(env, 256) != 0) {
        js_vm_fail_closed(env, "native VM local frame allocation failed");
        return;
    }
    jobject result = js_vm_execute_resource_by_token(env, cls, entryToken, NULL);
    (*env)->PopLocalFrame(env, result);
}

JS_LOCAL void JNICALL
jsn_r24(JNIEnv *env, jclass cls, jlong entryToken, jint arg0)
{
    if ((*env)->PushLocalFrame(env, 256) != 0) {
        js_vm_fail_closed(env, "native VM local frame allocation failed");
        return;
    }
    jobject boxed = (*env)->CallStaticObjectMethod(env, js_jni_cache.integer_class, js_jni_cache.integer_value_of, arg0);
    if ((*env)->ExceptionCheck(env) || !boxed) {
        (*env)->PopLocalFrame(env, NULL);
        return;
    }
    jobjectArray args = (*env)->NewObjectArray(env, 1, js_jni_cache.object_class, NULL);
    if ((*env)->ExceptionCheck(env) || !args) {
        (*env)->PopLocalFrame(env, NULL);
        return;
    }
    (*env)->SetObjectArrayElement(env, args, 0, boxed);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->PopLocalFrame(env, NULL);
        return;
    }
    jobject result = js_vm_execute_resource_by_token(env, cls, entryToken, args);
    (*env)->PopLocalFrame(env, result);
}


static const unsigned char JS_JSE_CLASS_DERIVE_LABEL[] = "javashroud-vbc4-jse-class-v1";

/* HKDF-SHA256 (RFC 5869) class-encryption key derivation. Runs ONLY inside the
 * sealed native kernel: ikm is the resident per-build runtime resource root key,
 * the label is the extract salt, info is keyId||salt. Byte-for-byte identical to
 * the Kotlin build-time derivation so a build-time key recomputes at runtime. */
static int js_hkdf_sha256_class_key(const unsigned char *info, int info_len, unsigned char *out, int out_len) {
    if (out_len < 1 || out_len > 255 * 32) return 0;
    unsigned char prk[32];
    const unsigned char *xparts[1];
    int xlens[1];
    unsigned char root[32];
    js_rrk_xor_assemble(&js_runtime_resource_key_shares[0][0], JS_RRK_SHARE_COUNT, root);
    xparts[0] = root;
    xlens[0] = 32;
    js_hmac_sha256_with_key(JS_JSE_CLASS_DERIVE_LABEL, (int)(sizeof(JS_JSE_CLASS_DERIVE_LABEL) - 1), xparts, xlens, 1, prk);
    js_vbc4_wipe_volatile(root, sizeof(root));
    unsigned char previous[32];
    int prev_len = 0;
    int produced = 0;
    unsigned char counter = 1;
    while (produced < out_len) {
        const unsigned char *eparts[3];
        int elens[3];
        int npart = 0;
        if (prev_len > 0) { eparts[npart] = previous; elens[npart] = prev_len; npart++; }
        eparts[npart] = info; elens[npart] = info_len; npart++;
        eparts[npart] = &counter; elens[npart] = 1; npart++;
        js_hmac_sha256_with_key(prk, 32, eparts, elens, npart, previous);
        prev_len = 32;
        int take = (32 < (out_len - produced)) ? 32 : (out_len - produced);
        memcpy(out + produced, previous, (size_t)take);
        produced += take;
        counter++;
    }
    js_vbc4_wipe_volatile(prk, sizeof(prk));
    js_vbc4_wipe_volatile(previous, sizeof(previous));
    return 1;
}


JS_LOCAL jbyteArray JNICALL
jsn_k10(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length)
{
    (void)cls;
    if (!js_runtime_resource_key_ready) return NULL;
    if (length < 1 || length > 64) return NULL;
    if (!keyIdArr || !saltArr) return NULL;
    jsize id_len = (*env)->GetArrayLength(env, keyIdArr);
    jsize salt_len = (*env)->GetArrayLength(env, saltArr);
    if (id_len < 0 || salt_len < 0 || (id_len + salt_len) > 4096) return NULL;    unsigned char *info = (unsigned char*)malloc((size_t)(id_len + salt_len) > 0 ? (size_t)(id_len + salt_len) : 1);
    if (!info) return NULL;
    if (id_len > 0) (*env)->GetByteArrayRegion(env, keyIdArr, 0, id_len, (jbyte*)info);
    if (salt_len > 0) (*env)->GetByteArrayRegion(env, saltArr, 0, salt_len, (jbyte*)(info + id_len));
    unsigned char derived[64];
    int ok = js_hkdf_sha256_class_key(info, (int)(id_len + salt_len), derived, (int)length);
    js_vbc4_wipe_volatile(info, (size_t)(id_len + salt_len));
    free(info);
    if (!ok) { js_vbc4_wipe_volatile(derived, sizeof(derived)); return NULL; }
    jbyteArray out = (*env)->NewByteArray(env, length);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, length, (jbyte*)derived);
    js_vbc4_wipe_volatile(derived, sizeof(derived));
    return out;
}

/* Fill a share with per-process entropy so a memory dump of any single share
 * reveals nothing about the root key. Mixes rdtsc, monotonic ticks, a stack
 * address and a rolling counter through a small xorshift; not a CSPRNG, but the
 * shares only need to be unpredictable per process for anti-dump dispersion. */
static volatile uint64_t js_rrk_entropy_roll = 0;
static void js_rrk_fill_entropy(unsigned char out[32]) {
    uint64_t s = js_vm_probe_rdtsc() ^ (js_vm_probe_monotonic_ticks() * 0x9E3779B97F4A7C15ULL);
    s ^= (uint64_t)(uintptr_t)&out;
    s ^= (js_rrk_entropy_roll += 0xA24BAED4963EE407ULL);
    if (s == 0) s = 0xD1B54A32D192ED03ULL;
    for (int i = 0; i < 32; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        out[i] = (unsigned char)(s & 0xFF);
    }
}

JS_LOCAL void JNICALL
jsn_k7(JNIEnv *env, jclass cls, jbyteArray keyArr)
{
    (void)cls;
    if (!keyArr || (*env)->GetArrayLength(env, keyArr) != 32) {
        js_runtime_resource_key_ready = 0;
        return;
    }
    jbyte *raw = (*env)->GetByteArrayElements(env, keyArr, NULL);
    if (!raw) {
        js_runtime_resource_key_ready = 0;
        return;
    }
    for (int s = 0; s < JS_RRK_SHARE_COUNT - 1; s++) js_rrk_fill_entropy(js_runtime_resource_key_shares[s]);
    for (int b = 0; b < 32; b++) {
        unsigned char acc = (unsigned char)raw[b];
        for (int s = 0; s < JS_RRK_SHARE_COUNT - 1; s++) acc = (unsigned char)(acc ^ js_runtime_resource_key_shares[s][b]);
        js_runtime_resource_key_shares[JS_RRK_SHARE_COUNT - 1][b] = acc;
    }
    (*env)->ReleaseByteArrayElements(env, keyArr, raw, JNI_ABORT);
    js_runtime_resource_key_ready = 1;
}

JS_LOCAL jobject JNICALL
jsn_r22(
    JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args)
{
    if ((*env)->PushLocalFrame(env, 4096) != 0) {
        return js_vm_fail_closed(env, "native VM local frame allocation failed");
    }
    jobject result = js_vm_execute_resource_by_token(env, cls, entryToken, args);
    return (*env)->PopLocalFrame(env, result);
}

JS_LOCAL void JNICALL
jsn_k8(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath)
{
    if (!resourcePath || entryToken == 0) { js_vm_fail_closed(env, NULL); return; }
    const char *path = j2c(env, resourcePath);
    if (!path) { js_vm_fail_closed(env, NULL); return; }
    js_vm_program *cached = js_vm_ephemeral_cache_get(entryToken, path);
    if (cached) { rls(env, resourcePath, path); return; }
    if (!js_vm_call_gate_mark_loading(entryToken, path)) { rls(env, resourcePath, path); return; }
    js_vm_program *program = js_vm_prepare_resource_program(env, cls, entryToken, resourcePath);
    if (program) {
        js_vm_program validation;
        memset(&validation, 0, sizeof(validation));
        if (!js_vm_build_execution_program_from_registers(program, &validation)) {
            char reason[384];
            snprintf(reason, sizeof(reason), "native VM preload validation failed at %s#%s%s err=%d reg=%d super=%d insn=%d",
                program->original_owner ? program->original_owner : "?",
                program->original_name ? program->original_name : "?",
                program->original_desc ? program->original_desc : "?",
                js_vm_last_validation_error, program->reg_program.insn_count, program->reg_program.super_count, program->insn_count);
            js_vm_clear_execution_program(&validation);
            js_vm_free_program(env, program);
            free(program);
            js_vm_call_gate_clear_loading(entryToken);
            rls(env, resourcePath, path);
            js_vm_fail_closed(env, reason);
            return;
        } else if (!js_vm_adopt_validated_execution_program(program, &validation)) {
            js_vm_clear_execution_program(&validation);
            js_vm_free_program(env, program);
            free(program);
            js_vm_call_gate_clear_loading(entryToken);
            rls(env, resourcePath, path);
            js_vm_fail_closed(env, "native VM preload validation produced no execution program");
            return;
        } else {
            js_vm_clear_execution_program(&validation);
        }
    }
    if (!program || !js_vm_ephemeral_cache_put(entryToken, path, program)) {
        if (program) { js_vm_free_program(env, program); free(program); }
        js_vm_call_gate_clear_loading(entryToken);
        rls(env, resourcePath, path);
        js_vm_fail_closed(env, "native VM preload validation failed");
        return;
    }
    js_vm_call_gate_clear_loading(entryToken);
    rls(env, resourcePath, path);
}

JS_LOCAL void JNICALL
jsn_k9(JNIEnv *env, jclass cls)
{
    jstring index_path = (*env)->NewStringUTF(env, "META-INF/.r/vm-current.idx");
    if (!index_path) { js_vm_clear_exception(env); return; }
    jbyteArray raw_index = js_vm_load_resource_bytes(env, cls, index_path);
    (*env)->DeleteLocalRef(env, index_path);
    if (!raw_index) {
        js_vm_clear_exception(env);
        index_path = (*env)->NewStringUTF(env, "META-INF/.r/vm.idx");
        if (!index_path) { js_vm_clear_exception(env); return; }
        raw_index = js_vm_load_resource_bytes(env, cls, index_path);
        (*env)->DeleteLocalRef(env, index_path);
    }
    if (!raw_index) {
        js_vm_clear_exception(env);
        return;
    }
    int raw_len = (*env)->GetArrayLength(env, raw_index);
    jbyte *raw_bytes = raw_len > 0 ? (*env)->GetByteArrayElements(env, raw_index, NULL) : NULL;
    int index_len = 0;
    unsigned char *index_bytes = NULL;
    if (raw_bytes) {
        index_bytes = js_runtime_resource_decode_owned((const unsigned char*)raw_bytes, raw_len, &index_len);
        js_vbc4_wipe_volatile(raw_bytes, (size_t)raw_len);
        (*env)->ReleaseByteArrayElements(env, raw_index, raw_bytes, JNI_ABORT);
    }
    if (!index_bytes || index_len <= 0) {
        if (index_bytes) { js_vbc4_wipe_volatile(index_bytes, (size_t)index_len); free(index_bytes); }
        js_vm_fail_closed(env, "invalid VM preload index");
        return;
    }
    js_vm_register_preload_index_entries(index_bytes, index_len);
    js_vm_preload_in_progress++;
    int line_start = 0;
    for (int i = 0; i <= index_len; i++) {
        if (i != index_len && index_bytes[i] != '\n' && index_bytes[i] != '\r') continue;
        int line_end = i;
        while (line_start < line_end && (index_bytes[line_start] == ' ' || index_bytes[line_start] == '\t')) line_start++;
        while (line_end > line_start && (index_bytes[line_end - 1] == ' ' || index_bytes[line_end - 1] == '\t')) line_end--;
        if (line_end > line_start) {
            int sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1, sep5 = -1;
            for (int p = line_start; p < line_end; p++) {
                if (index_bytes[p] != '|') continue;
                if (sep1 < 0) sep1 = p;
                else if (sep2 < 0) sep2 = p;
                else if (sep3 < 0) sep3 = p;
                else if (sep4 < 0) sep4 = p;
                else { sep5 = p; break; }
            }
            if (sep1 == line_start + 1 && index_bytes[line_start] == 'A') {
                while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
                line_start = i + 1;
                continue;
            }
            if (sep1 <= line_start || sep1 + 1 >= line_end || sep1 - line_start > 16) {
                js_vm_preload_in_progress--;
                js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                free(index_bytes);
                js_vm_fail_closed(env, "malformed VM preload index");
                return;
            }
            unsigned long long token = 0;
            for (int p = line_start; p < sep1; p++) {
                unsigned char ch = index_bytes[p];
                int nibble = (ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' && ch <= 'f') ? (ch - 'a' + 10) : (ch >= 'A' && ch <= 'F') ? (ch - 'A' + 10) : -1;
                if (nibble < 0) {
                    js_vm_preload_in_progress--;
                    js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                    free(index_bytes);
                    js_vm_fail_closed(env, "malformed VM preload token");
                    return;
                }
                token = (token << 4) | (unsigned long long)nibble;
            }
            char *resource_path = NULL;
            char *manifest_path = NULL;
            char *binding_resource_path = NULL;
            char *binding_manifest_path = NULL;
            uint32_t shard_count = 0;
            if (sep2 > 0 && sep3 > 0) {
                resource_path = js_substr_dup((const char*)index_bytes + sep1 + 1, (size_t)(sep2 - sep1 - 1));
                manifest_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(sep3 - sep2 - 1));
                int shard_end = sep4 > 0 ? sep4 : line_end;
                char *shard_text = js_substr_dup((const char*)index_bytes + sep3 + 1, (size_t)(shard_end - sep3 - 1));
                if (!shard_text || !js_parse_u32_token(shard_text, &shard_count)) shard_count = 0;
                if (shard_text) { js_vbc4_wipe_volatile(shard_text, strlen(shard_text)); free(shard_text); }
                if (sep4 > 0) {
                    int binding_resource_end = sep5 > 0 ? sep5 : line_end;
                    binding_resource_path = js_substr_dup((const char*)index_bytes + sep4 + 1, (size_t)(binding_resource_end - sep4 - 1));
                    if (sep5 > 0) binding_manifest_path = js_substr_dup((const char*)index_bytes + sep5 + 1, (size_t)(line_end - sep5 - 1));
                }
            } else {
                resource_path = js_substr_dup((const char*)index_bytes + sep1 + 1, (size_t)(line_end - sep1 - 1));
            }
            const char *preload_binding_path = binding_resource_path && binding_resource_path[0] ? binding_resource_path : resource_path;
            const char *preload_binding_manifest = binding_manifest_path && binding_manifest_path[0] ? binding_manifest_path : manifest_path;
            js_vm_resource_alias_register(preload_binding_path, resource_path);
            if (manifest_path && preload_binding_manifest) js_vm_resource_alias_register(preload_binding_manifest, manifest_path);
            if (!resource_path || (sep2 > 0 && sep3 > 0 && (!manifest_path || shard_count < 2))) {
                if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); }
                if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                js_vm_preload_in_progress--;
                js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                free(index_bytes);
                js_vm_fail_closed(env, NULL);
                return;
            }
            if (manifest_path) js_vm_shared_dispatch_mix_preload((jlong)token, preload_binding_path, preload_binding_manifest, shard_count);
            jstring resource_jstr = (*env)->NewStringUTF(env, preload_binding_path);
            char *cache_resource_path = preload_binding_path ? js_strdup(preload_binding_path) : NULL;
            if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); manifest_path = NULL; }
            js_vbc4_wipe_volatile(resource_path, strlen(resource_path));
            free(resource_path);
            resource_path = NULL;
            if (!resource_jstr) {
                js_vm_clear_exception(env);
                js_vm_preload_in_progress--;
                js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                free(index_bytes);
                js_vm_fail_closed(env, NULL);
                return;
            }
            const char *cache_path = cache_resource_path ? cache_resource_path : "";
            if (!js_vm_call_gate_mark_loading((jlong)token, cache_path)) {
                /* The index registration should already have opened this gate; if not, fail closed below. */
            }
            js_vm_program *program = js_vm_prepare_resource_program_bound(env, cls, (jlong)token, resource_jstr, cache_path);
            if (program) {
                js_vm_program validation;
                memset(&validation, 0, sizeof(validation));
                if (!js_vm_build_execution_program_from_registers(program, &validation)) {
                    char reason[384];
                    snprintf(reason, sizeof(reason), "native VM preload validation failed at %s#%s%s err=%d reg=%d super=%d insn=%d",
                        program->original_owner ? program->original_owner : "?",
                        program->original_name ? program->original_name : "?",
                        program->original_desc ? program->original_desc : "?",
                        js_vm_last_validation_error, program->reg_program.insn_count, program->reg_program.super_count, program->insn_count);
                    js_vm_clear_execution_program(&validation);
                    js_vm_free_program(env, program);
                    free(program);
                    js_vm_call_gate_clear_loading((jlong)token);
                    if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                    if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                    if (cache_resource_path) { js_vbc4_wipe_volatile(cache_resource_path, strlen(cache_resource_path)); free(cache_resource_path); }
                    (*env)->DeleteLocalRef(env, resource_jstr);
                    js_vm_preload_in_progress--;
                    js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                    free(index_bytes);
                    js_vm_fail_closed(env, reason);
                    return;
                } else if (!js_vm_adopt_validated_execution_program(program, &validation)) {
                    js_vm_clear_execution_program(&validation);
                    js_vm_free_program(env, program);
                    free(program);
                    js_vm_call_gate_clear_loading((jlong)token);
                    if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                    if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                    if (cache_resource_path) { js_vbc4_wipe_volatile(cache_resource_path, strlen(cache_resource_path)); free(cache_resource_path); }
                    (*env)->DeleteLocalRef(env, resource_jstr);
                    js_vm_preload_in_progress--;
                    js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                    free(index_bytes);
                    js_vm_fail_closed(env, "native VM preload validation produced no execution program");
                    return;
                } else {
                    js_vm_clear_execution_program(&validation);
                }
            }
            if (!program || !js_vm_ephemeral_cache_put((jlong)token, cache_path, program)) {
                if (program) { js_vm_free_program(env, program); free(program); }
                js_vm_call_gate_clear_loading((jlong)token);
                if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                if (cache_resource_path) { js_vbc4_wipe_volatile(cache_resource_path, strlen(cache_resource_path)); free(cache_resource_path); }
                (*env)->DeleteLocalRef(env, resource_jstr);
                js_vm_preload_in_progress--;
                js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                free(index_bytes);
                {
                    char preload_reason[160];
                    snprintf(preload_reason, sizeof(preload_reason), "native VM preload validation failed (stage=%s)", js_vm_last_prepare_stage[0] ? js_vm_last_prepare_stage : "program");
                    js_vm_fail_closed(env, preload_reason);
                }
                return;
            }
            js_vm_call_gate_clear_loading((jlong)token);
            if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
            if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
            if (cache_resource_path) { js_vbc4_wipe_volatile(cache_resource_path, strlen(cache_resource_path)); free(cache_resource_path); }
            (*env)->DeleteLocalRef(env, resource_jstr);
            if ((*env)->ExceptionCheck(env)) {
                js_vm_preload_in_progress--;
                js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                free(index_bytes);
                return;
            }
        }
        while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
        line_start = i + 1;
    }
    js_vm_preload_in_progress--;
    js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
    free(index_bytes);
}
JS_HIDDEN char* js_lookup_bound_class(JNIEnv *env, const char *original) {
    if (!original) return NULL;
    unsigned long long original_hash = 0xcbf29ce484222325ULL;
    for (const unsigned char *p = (const unsigned char*)original; *p; ++p) {
        original_hash ^= (unsigned long long)(*p);
        original_hash *= 0x100000001b3ULL;
    }
    char original_key[17];
    snprintf(original_key, sizeof(original_key), "%016llx", original_hash);
    char *loader_owner = js_helper_owner("Jni", "Micro", "kernel", "Helper");
    int is_loader_owner = loader_owner && !strcmp(original, loader_owner);
    free(loader_owner);
    if (is_loader_owner) {
        char *loader = js_first_loader_owner_from_property(env);
        if (loader && loader[0]) return loader;
        free(loader);
    }
    char *bindings = sys_prop(env, "j.b");
    if (!bindings) return NULL;
    size_t original_len = strlen(original_key);
    char *cursor = bindings;
    while (*cursor) {
        char *line = cursor;
        char *eol = strchr(cursor, '\n');
        if (eol) *eol = 0;
        size_t line_len = strlen(line);
        while (line_len > 0 && (line[line_len - 1] == '\r' || line[line_len - 1] == ' ' || line[line_len - 1] == '\t')) {
            line[--line_len] = 0;
        }
        if (line_len > original_len + 1 && !strncmp(line, original_key, original_len) && line[original_len] == '=') {
            char *mapped = js_strdup(line + original_len + 1);
            free(bindings);
            return mapped;
        }
        if (!eol) break;
        cursor = eol + 1;
    }
    free(bindings);
    return NULL;
}
JS_HIDDEN char* js_lookup_bound_method(JNIEnv *env, const char *original_class, const char *method_name, const char *signature) {
    if (!original_class || !method_name || !signature) return NULL;
    unsigned long long key_hash = 0xcbf29ce484222325ULL;
    for (const unsigned char *p = (const unsigned char*)original_class; *p; ++p) { key_hash ^= (unsigned long long)(*p); key_hash *= 0x100000001b3ULL; }
    key_hash ^= (unsigned long long)'#'; key_hash *= 0x100000001b3ULL;
    for (const unsigned char *p = (const unsigned char*)method_name; *p; ++p) { key_hash ^= (unsigned long long)(*p); key_hash *= 0x100000001b3ULL; }
    key_hash ^= (unsigned long long)'#'; key_hash *= 0x100000001b3ULL;
    for (const unsigned char *p = (const unsigned char*)signature; *p; ++p) { key_hash ^= (unsigned long long)(*p); key_hash *= 0x100000001b3ULL; }
    char lookup_key[17];
    snprintf(lookup_key, sizeof(lookup_key), "%016llx", key_hash);
    char *bindings = sys_prop(env, "j.m");
    if (!bindings) return NULL;
    size_t key_len = strlen(lookup_key);
    char *cursor = bindings;
    while (*cursor) {
        char *line = cursor;
        char *eol = strchr(cursor, '\n');
        if (eol) *eol = 0;
        size_t line_len = strlen(line);
        while (line_len > 0 && (line[line_len - 1] == '\r' || line[line_len - 1] == ' ' || line[line_len - 1] == '\t')) {
            line[--line_len] = 0;
        }
        if (line_len > key_len + 1 && !strncmp(line, lookup_key, key_len) && line[key_len] == '=') {
            char *mapped = js_strdup(line + key_len + 1);
            free(bindings);
            return mapped;
        }
        if (!eol) break;
        cursor = eol + 1;
    }
    free(bindings);
    return NULL;
}
JS_HIDDEN void js_vm_mark_hot_integrity_baseline_clean(void) {
    js_vm_hot_integrity_baseline_clean = js_vm_hot_integrity_clean();
}

JS_HIDDEN void js_runtime_on_unload_cleanup(JNIEnv *env) {
    js_vm_ephemeral_cache_clear(env);
    js_vbc4_wipe_volatile(js_runtime_resource_key_shares, sizeof(js_runtime_resource_key_shares));
    js_runtime_resource_key_ready = 0;
    if (env) js_jni_cache_destroy(env);
}

/* END MOVED JS_HELPERS CORE */
