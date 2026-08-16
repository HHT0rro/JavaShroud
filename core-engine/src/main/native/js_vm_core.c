#include "js_vm_core.h"
#include "js_jni_runtime.h"
#include "js_vm_symbol.h"
#include "js_machine_id.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "native_secrets.inc"

#define JS_VM_MAXS 0xFE
#define JS_VM_UNSUPPORTED 0xFF

#if defined(_WIN32)
static js_vm_program *js_vm_active_program_stack[64];
static int js_vm_active_program_depth = 0;
#elif defined(_MSC_VER)
__declspec(thread) static js_vm_program *js_vm_active_program_stack[64];
__declspec(thread) static int js_vm_active_program_depth = 0;
#elif defined(__GNUC__) || defined(__clang__)
static js_vm_program *js_vm_active_program_stack[64];
static int js_vm_active_program_depth = 0;
#else
static js_vm_program *js_vm_active_program_stack[64];
static int js_vm_active_program_depth = 0;
#endif

/* Active host class loader for the currently executing virtualized method.
 * The dispatch entry receives the calling obfuscated class; symbol resolution
 * falls back to this loader for app-classpath-only classes. */
#if defined(_WIN32)
static jobject js_vm_active_host_loader = NULL;
#elif defined(_MSC_VER)
__declspec(thread) static jobject js_vm_active_host_loader = NULL;
#elif defined(__GNUC__) || defined(__clang__)
static jobject js_vm_active_host_loader = NULL;
#else
static jobject js_vm_active_host_loader = NULL;
#endif

JS_HIDDEN jobject js_vm_get_active_host_loader(void) { return js_vm_active_host_loader; }

JS_HIDDEN void js_vm_set_active_host_loader(jobject loader) { js_vm_active_host_loader = loader; }

static void js_vm_debug_method_lookup_probe(const char *label, JNIEnv *env, jclass cls, jobject obj, const char *name, const char *desc, int is_static);
static void js_runtime_boot_material_clear(void);
JS_HIDDEN int js_vm_sensitive_path_guard(JNIEnv *env, const void *entry, int clear_boot_material);
static void js_vm_debug_alloc_probe(const char *label, JNIEnv *env, jclass cls, const char *tag);
static int js_vm_execute_with_preset_locals(JNIEnv *env, js_vm_program *p, jobjectArray args, const js_vm_value *preset_locals, int preset_count, char ret_desc, js_vm_value *ret);
JS_HIDDEN int js_vm_execute_prepared_program_int_int(JNIEnv *env, js_vm_program *program, jint arg0, jint *out);

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

static js_vm_program* js_vm_active_program_current(void) {
    if (js_vm_active_program_depth <= 0) return NULL;
    return js_vm_active_program_stack[js_vm_active_program_depth - 1];
}

JS_HIDDEN js_vm_program* js_vm_active_program_find_by_identity(const unsigned char method_identity[32]) {
    if (!method_identity) return NULL;
    for (int i = js_vm_active_program_depth - 1; i >= 0; i--) {
        js_vm_program *program = js_vm_active_program_stack[i];
        if (program && memcmp(program->method_identity, method_identity, 32) == 0) return program;
    }
    return NULL;
}

static int js_vm_execute_register_with_preset_locals(JNIEnv *env, js_vm_program *p, jobjectArray args, const js_vm_value *preset_locals, int preset_count, char ret_desc, js_vm_value *ret) {
    if (!p || !js_vm_verify_runtime_session(p)) return 0;
    js_vm_program execution;
    memset(&execution, 0, sizeof(execution));
    if (p->cached_execution_ready && p->insns && p->insn_count > 0) {
        /* Hot path: flat-copy the validated program instead of deep cloning it
         * per call. The interpreter mutates only the (opcode, opcode_epoch)
         * fields of the resident array during execution (per-step rewrap and
         * window rotation reseal), while operand arrays are read-only (operand
         * decode lands in a per-fetch buffer). So one flat malloc+memcpy keeps
         * the private mutable state, and the persistent program keeps owning
         * the shared operand storage. Symbol resolution results are JVM-global,
         * so the symbol cache lives on the persistent program as an append-only
         * shared table instead of being rebuilt and wiped per call. */
        js_vm_copy_execution_program_header(&execution, p);
        execution.insns = (js_vm_insn*)malloc((size_t)p->insn_count * sizeof(js_vm_insn));
        if (!execution.insns) {
            js_vm_clear_execution_program(&execution);
            return 0;
        }
        memcpy(execution.insns, p->insns, (size_t)p->insn_count * sizeof(js_vm_insn));
        execution.insn_count = p->insn_count;
        execution.borrowed_insns = 0;
        execution.borrowed_insn_operands = 1;
        execution.cached_execution_ready = 0;
        execution.symbols = p->symbols;
        execution.symbol_count = p->symbol_count;
        execution.symbol_capacity = p->symbol_capacity;
        execution.symbol_cache_owner = p->symbol_cache_owner ? p->symbol_cache_owner : p;
    } else if (!js_vm_build_execution_program_from_registers(p, &execution)) {
        js_vm_clear_execution_program(&execution);
        return 0;
    }
    int pushed_active_program = js_vm_active_program_push(&execution);
    int ok = js_vm_execute_with_preset_locals(env, &execution, args, preset_locals, preset_count, ret_desc, ret);
    if (pushed_active_program) js_vm_active_program_pop();
    /* Per-run symbol caches are only owned privately when the execution was
     * built from registers; cached programs share the persistent table. */
    if (!execution.symbol_cache_owner && execution.symbols) {
        for (int si = 0; si < execution.symbol_count; si++) js_vm_symbol_cache_clear_entry(env, &execution.symbols[si]);
        js_vbc4_wipe_volatile(execution.symbols, (size_t)execution.symbol_count * sizeof(js_vm_symbol_cache_entry));
        free(execution.symbols);
        execution.symbols = NULL;
        execution.symbol_count = 0;
    }
    js_vm_clear_execution_program(&execution);
    return ok;
}

JS_HIDDEN int js_vm_execute_register(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret) {
    return js_vm_execute_register_with_preset_locals(env, p, args, NULL, 0, ret_desc, ret);
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

JS_HIDDEN int js_vm_method_is_instance(js_vm_program *p) {
    return p && !p->is_static;
}

JS_HIDDEN int js_vm_ldc_type_matches_owner_identity(const char *type_desc, js_vm_program *p) {
    if (!type_desc || !p) return 0;
    const char *owner = type_desc;
    char *owned = NULL;
    if (type_desc[0] == 'L') {
        const char *semi = strchr(type_desc, ';');
        if (!semi || semi[1] != 0 || semi == type_desc + 1) return 0;
        owned = js_vm_copy_range(type_desc + 1, (size_t)(semi - type_desc - 1));
        owner = owned;
    }
    unsigned char identity[32];
    int match = owner && js_vm_owner_identity_for_name(owner, identity) && memcmp(identity, p->owner_identity, sizeof(identity)) == 0;
    js_vbc4_wipe_volatile(identity, sizeof(identity));
    if (owned) { js_vbc4_wipe_volatile(owned, strlen(owned)); free(owned); }
    return match;
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

static jmethodID js_vm_method_from_object(JNIEnv *env, jobject obj, const char *name, const char *sig) {
    if (!obj || !name || !sig) return NULL;
    jclass cls = (*env)->GetObjectClass(env, obj);
    if ((*env)->ExceptionCheck(env) || !cls) { js_vm_clear_exception(env); return NULL; }
    js_vm_debug_method_lookup_probe("method-from-object", env, cls, obj, name, sig, 0);
    jmethodID mid = (*env)->GetMethodID(env, cls, name, sig);
    (*env)->DeleteLocalRef(env, cls);
    if ((*env)->ExceptionCheck(env) || !mid) { js_vm_clear_exception(env); return NULL; }
    return mid;
}

JS_HIDDEN int js_vm_boxed_arg(JNIEnv *env, jobject obj, js_vm_value *out) {
    if (!obj) { *out = js_vm_null_value(); return 1; }
    if (!js_jni_cache.initialized) return 0;
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.integer_class)) { *out = js_vm_int_value((*env)->GetIntField(env, obj, js_jni_cache.integer_value_field)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.boolean_class)) { *out = js_vm_int_value((*env)->GetBooleanField(env, obj, js_jni_cache.boolean_value_field) ? 1 : 0); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.byte_class)) { *out = js_vm_int_value((jint)(*env)->GetByteField(env, obj, js_jni_cache.byte_value_field)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.short_class)) { *out = js_vm_int_value((jint)(*env)->GetShortField(env, obj, js_jni_cache.short_value_field)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.character_class)) { *out = js_vm_int_value((jint)(*env)->GetCharField(env, obj, js_jni_cache.character_value_field)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.long_class)) { *out = js_vm_long_value((*env)->GetLongField(env, obj, js_jni_cache.long_value_field)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.float_class)) { *out = js_vm_float_value((*env)->GetFloatField(env, obj, js_jni_cache.float_value_field)); return !(*env)->ExceptionCheck(env); }
    if ((*env)->IsInstanceOf(env, obj, js_jni_cache.double_class)) { *out = js_vm_double_value((*env)->GetDoubleField(env, obj, js_jni_cache.double_value_field)); return !(*env)->ExceptionCheck(env); }
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

static jobject js_vm_alloc_boxed_value(JNIEnv *env, jclass cls, jfieldID field, char tag, jvalue value) {
    if (!env || !cls || !field) return NULL;
    char tag_text[2] = { tag, 0 };
    js_vm_debug_alloc_probe("boxed-value", env, cls, tag_text);
    jobject boxed = (*env)->AllocObject(env, cls);
    if ((*env)->ExceptionCheck(env) || !boxed) return NULL;
    switch (tag) {
        case 'Z': (*env)->SetBooleanField(env, boxed, field, value.z); break;
        case 'B': (*env)->SetByteField(env, boxed, field, value.b); break;
        case 'S': (*env)->SetShortField(env, boxed, field, value.s); break;
        case 'C': (*env)->SetCharField(env, boxed, field, value.c); break;
        case 'I': (*env)->SetIntField(env, boxed, field, value.i); break;
        case 'J': (*env)->SetLongField(env, boxed, field, value.j); break;
        case 'F': (*env)->SetFloatField(env, boxed, field, value.f); break;
        case 'D': (*env)->SetDoubleField(env, boxed, field, value.d); break;
        default: return NULL;
    }
    return (*env)->ExceptionCheck(env) ? NULL : boxed;
}

JS_HIDDEN jobject js_vm_box_jvalue_arg(JNIEnv *env, char tag, jvalue value) {
    if (!js_jni_cache.initialized) return NULL;
    switch (tag) {
        case 'Z': return js_vm_alloc_boxed_value(env, js_jni_cache.boolean_class, js_jni_cache.boolean_value_field, tag, value);
        case 'B': return js_vm_alloc_boxed_value(env, js_jni_cache.byte_class, js_jni_cache.byte_value_field, tag, value);
        case 'S': return js_vm_alloc_boxed_value(env, js_jni_cache.short_class, js_jni_cache.short_value_field, tag, value);
        case 'C': return js_vm_alloc_boxed_value(env, js_jni_cache.character_class, js_jni_cache.character_value_field, tag, value);
        case 'I': return js_vm_alloc_boxed_value(env, js_jni_cache.integer_class, js_jni_cache.integer_value_field, tag, value);
        case 'J': return js_vm_alloc_boxed_value(env, js_jni_cache.long_class, js_jni_cache.long_value_field, tag, value);
        case 'F': return js_vm_alloc_boxed_value(env, js_jni_cache.float_class, js_jni_cache.float_value_field, tag, value);
        case 'D': return js_vm_alloc_boxed_value(env, js_jni_cache.double_class, js_jni_cache.double_value_field, tag, value);
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

JS_HIDDEN int js_vm_monitor_enter(JNIEnv *env, js_vm_value value) {
    jobject monitor = NULL;
    if (!js_vm_to_object(value, &monitor)) return 0;
    if (!monitor) return js_vm_throw_new(env, "java/lang/NullPointerException", "monitorenter on null");

    jint result = (*env)->MonitorEnter(env, monitor);
    if (result == JNI_OK) return !(*env)->ExceptionCheck(env);
    if (!(*env)->ExceptionCheck(env)) {
        return js_vm_throw_new(env, "java/lang/InternalError", "JNI MonitorEnter failed");
    }
    return 0;
}

JS_HIDDEN int js_vm_monitor_exit(JNIEnv *env, js_vm_value value) {
    jobject monitor = NULL;
    if (!js_vm_to_object(value, &monitor)) return 0;
    if (!monitor) return js_vm_throw_new(env, "java/lang/NullPointerException", "monitorexit on null");

    jint result = (*env)->MonitorExit(env, monitor);
    if (result == JNI_OK) return !(*env)->ExceptionCheck(env);
    if (!(*env)->ExceptionCheck(env)) {
        return js_vm_throw_new(env, "java/lang/IllegalMonitorStateException", "current thread does not own monitor");
    }
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
        if (!program->borrowed_insns) {
            js_vbc4_wipe_volatile(program->insns, (size_t)program->insn_count * sizeof(js_vm_insn));
            free(program->insns);
        }
    }
    if (program->exceptions && !program->borrowed_exceptions) {
        js_vbc4_wipe_volatile(program->exceptions, (size_t)program->exception_count * sizeof(js_vm_exception));
        free(program->exceptions);
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
    dst->borrowed_exceptions = 1;
    dst->cfg_exceptions_decoded = src->cfg_exceptions_decoded;
    dst->max_stack = src->max_stack > 0 ? src->max_stack : 1;
    dst->max_locals = src->max_locals > 0 ? src->max_locals : 1;
    dst->mac_key = src->mac_key;
    dst->build_seed = src->build_seed;
    dst->key_mask = src->key_mask;
    memcpy(dst->nonce, src->nonce, sizeof(dst->nonce));
    memcpy(dst->session_leaf, src->session_leaf, sizeof(dst->session_leaf));
    memcpy(dst->session_tag, src->session_tag, sizeof(dst->session_tag));
    dst->session_bound = src->session_bound;
    dst->metadata_cp_index = src->metadata_cp_index;
    dst->method_local_profile = src->method_local_profile;
    dst->native_vm_profile_id = src->native_vm_profile_id;
    dst->dispatch_profile_tag = src->dispatch_profile_tag;
    dst->vbc4_flags = src->vbc4_flags;
    dst->nested_vm_profile = src->nested_vm_profile;
    dst->entry_token = src->entry_token;
    dst->return_desc = src->return_desc;
    memcpy(dst->method_identity, src->method_identity, sizeof(dst->method_identity));
    memcpy(dst->owner_identity, src->owner_identity, sizeof(dst->owner_identity));
    dst->argument_tags = src->argument_tags;
    dst->argument_count = src->argument_count;
    dst->resource_path = src->resource_path;
    dst->is_static = src->is_static;
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
    if (!program->borrowed_insns) {
        js_vbc4_wipe_volatile(program->insns, (size_t)program->insn_count * sizeof(js_vm_insn));
        free(program->insns);
    }
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
    if (program->exceptions && !program->borrowed_exceptions) {
        js_vbc4_wipe_volatile(program->exceptions, (size_t)program->exception_count * sizeof(js_vm_exception));
        free(program->exceptions);
    }
    program->exceptions = validation->exceptions;
    program->exception_count = validation->exception_count;
    program->borrowed_exceptions = 0;
    program->cfg_exceptions_decoded = validation->cfg_exceptions_decoded;
    validation->insns = NULL;
    validation->insn_count = 0;
    validation->borrowed_insns = 0;
    validation->borrowed_insn_operands = 0;
    validation->cached_execution_ready = 0;
    validation->exceptions = NULL;
    validation->exception_count = 0;
    validation->borrowed_exceptions = 0;
    validation->cfg_exceptions_decoded = 0;
    return 1;
}

JS_HIDDEN int js_vm_clone_cached_execution_program(js_vm_program *source, js_vm_program *execution) {
    if (!source || !execution || !source->cached_execution_ready || !source->insns || source->insn_count <= 0) return 0;
    js_vm_copy_execution_program_header(execution, source);
    execution->insns = (js_vm_insn*)calloc((size_t)source->insn_count, sizeof(js_vm_insn));
    if (!execution->insns) return 0;
    memcpy(execution->insns, source->insns, (size_t)source->insn_count * sizeof(js_vm_insn));
    execution->insn_count = source->insn_count;
    execution->borrowed_insn_operands = 0;
    execution->borrowed_insns = 0;
    execution->cached_execution_ready = 0;
    for (int i = 0; i < source->insn_count; i++) execution->insns[i].ops = NULL;
    for (int i = 0; i < source->insn_count; i++) {
        if (source->insns[i].op_count <= 0 || !source->insns[i].ops) {
            execution->insns[i].ops = NULL;
            continue;
        }
        execution->insns[i].ops = (jint*)calloc((size_t)source->insns[i].op_count, sizeof(jint));
        if (!execution->insns[i].ops) {
            js_vm_clear_execution_program(execution);
            return 0;
        }
        memcpy(execution->insns[i].ops, source->insns[i].ops, (size_t)source->insns[i].op_count * sizeof(jint));
    }
    return 1;
}

static int js_vm_valid_method_lookup_name(const char *name) {
    if (!name || !name[0]) return 0;
    if (strcmp(name, "<init>") == 0 || strcmp(name, "<clinit>") == 0) return 1;
    for (const unsigned char *p = (const unsigned char*)name; *p; p++) {
        if (*p <= 0x20u || *p >= 0x7fu || *p == '.' || *p == '/' || *p == ';' || *p == '[' || *p == '(' || *p == ')') return 0;
    }
    return 1;
}

static int js_vm_valid_method_lookup(const char *name, const char *desc) {
    char *tags = NULL;
    int argc = 0;
    if (!js_vm_valid_method_lookup_name(name) || !desc || !desc[0]) return 0;
    if (strlen(name) > 512u || strlen(desc) > 4096u) return 0;
    if (!js_vm_descriptor_arg_tags(desc, &tags, &argc)) return 0;
    free(tags);
    return argc >= 0 && js_vm_descriptor_return_tag(desc) != 0;
}

static int js_vm_debug_native_enabled(void) {
    const char *debug = getenv("JAVASHROUD_DEBUG_NATIVE_LOAD");
    return debug && debug[0] && debug[0] != '0';
}

static void js_vm_debug_method_lookup_probe(const char *label, JNIEnv *env, jclass cls, jobject obj, const char *name, const char *desc, int is_static) {
    if (!js_vm_debug_native_enabled()) return;
    const char *log_path = getenv("JAVASHROUD_DEBUG_NATIVE_LOG");
    FILE *out = stderr;
    if (log_path && log_path[0]) {
        FILE *file = fopen(log_path, "ab");
        if (file) out = file;
    }
    fprintf(out,
        "JavaShroud native VM method lookup: %s env=%p cls=%p obj=%p static=%d name=%.120s desc=%.180s\n",
        label ? label : "<null>",
        (void *)env,
        (void *)cls,
        (void *)obj,
        is_static,
        name ? name : "<null>",
        desc ? desc : "<null>");
    if (out != stderr) fclose(out);
}

static void js_vm_debug_alloc_probe(const char *label, JNIEnv *env, jclass cls, const char *tag) {
    if (!js_vm_debug_native_enabled()) return;
    js_vm_program *program = js_vm_active_program_current();
    const char *log_path = getenv("JAVASHROUD_DEBUG_NATIVE_LOG");
    FILE *out = stderr;
    if (log_path && log_path[0]) {
        FILE *file = fopen(log_path, "ab");
        if (file) out = file;
    }
    fprintf(out,
        "JavaShroud native VM alloc: %s env=%p cls=%p tag=%.80s entry=%016llx\n",
        label ? label : "<null>",
        (void *)env,
        (void *)cls,
        tag ? tag : "<null>",
        (unsigned long long)(program ? program->entry_token : 0));
    if (out != stderr) fclose(out);
}

static char* js_vm_bounded_method_lookup_copy(const char *value, size_t max_len) {
    if (!value || max_len == 0u) return NULL;
    size_t len = 0;
    while (len <= max_len && value[len]) len++;
    if (len == 0u || len > max_len) return NULL;
    char *copy = (char*)malloc(len + 1u);
    if (!copy) return NULL;
    memcpy(copy, value, len);
    copy[len] = 0;
    return copy;
}

static jmethodID js_vm_lookup_valid_method_id(JNIEnv *env, jclass cls, const char *name, const char *desc, int is_static) {
    if (!env || !cls || !js_vm_valid_method_lookup(name, desc)) return NULL;
    char *safe_name = js_vm_bounded_method_lookup_copy(name, 512u);
    char *safe_desc = js_vm_bounded_method_lookup_copy(desc, 4096u);
    if (!safe_name || !safe_desc) {
        free(safe_name);
        free(safe_desc);
        return NULL;
    }
    js_vm_debug_method_lookup_probe("valid-method-id", env, cls, NULL, safe_name, safe_desc, is_static);
    jmethodID mid = is_static ? (*env)->GetStaticMethodID(env, cls, safe_name, safe_desc) : (*env)->GetMethodID(env, cls, safe_name, safe_desc);
    js_vbc4_wipe_volatile(safe_name, strlen(safe_name));
    js_vbc4_wipe_volatile(safe_desc, strlen(safe_desc));
    free(safe_name);
    free(safe_desc);
    return mid;
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

#define JS_VBC4_CFG_MODULUS 65536u
#define JS_VBC4_CFG_MASK 0xFFFFu

static uint32_t js_vbc4_cfg_multiplier(int seed, int instruction_count) {
    return (((uint32_t)seed ^ js_vbc4_rotl32_core((uint32_t)instruction_count, 7) ^ 0x6D2B79F5u) & JS_VBC4_CFG_MASK) | 1u;
}

static uint32_t js_vbc4_cfg_offset(int seed, int instruction_count) {
    uint32_t value = js_vbc4_rotl32_core((uint32_t)seed, 13) ^ ((uint32_t)instruction_count * 0x045D9F3Bu) ^ 0x27D4EB2Du;
    return value & JS_VBC4_CFG_MASK;
}

static uint32_t js_vbc4_mod_inverse(uint32_t value) {
    int64_t t = 0, next_t = 1;
    int64_t r = JS_VBC4_CFG_MODULUS, next_r = value % JS_VBC4_CFG_MODULUS;
    while (next_r != 0) {
        int64_t q = r / next_r;
        int64_t tmp_t = t - q * next_t; t = next_t; next_t = tmp_t;
        int64_t tmp_r = r - q * next_r; r = next_r; next_r = tmp_r;
    }
    if (r != 1) return 0;
    t %= (int64_t)JS_VBC4_CFG_MODULUS;
    if (t < 0) t += JS_VBC4_CFG_MODULUS;
    return (uint32_t)t;
}

static int js_vbc4_cfg_decode_index(int seed, int instruction_count, int encoded) {
    if (instruction_count <= 0 || instruction_count > 0xFFFF || encoded < 0 || encoded > (int)JS_VBC4_CFG_MASK) return -1;
    uint32_t multiplier = js_vbc4_cfg_multiplier(seed, instruction_count);
    uint32_t inverse = js_vbc4_mod_inverse(multiplier);
    if (inverse == 0u) return -1;
    uint32_t offset = js_vbc4_cfg_offset(seed, instruction_count);
    uint32_t normalized = ((uint32_t)encoded - offset) & JS_VBC4_CFG_MASK;
    uint32_t decoded = (uint32_t)(((uint64_t)normalized * inverse) & JS_VBC4_CFG_MASK);
    return decoded <= (uint32_t)instruction_count ? (int)decoded : -1;
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

JS_PROTECTED void js_vm_init_resident_key_mask(js_vm_program *p, const unsigned char nonce[16]) {
    if (!p) return;
    p->key_mask = js_vm_resident_key_mask_from_nonce(nonce) ^ 0x6A09E667;
}

JS_PROTECTED void js_vm_store_resident_build_seed(js_vm_program *p, int build_seed) {
    if (!p) return;
    p->build_seed = build_seed ^ js_vm_resident_key_mask(p);
}

JS_PROTECTED int js_vm_load_resident_build_seed(const js_vm_program *p) {
    return p ? (p->build_seed ^ js_vm_resident_key_mask(p)) : 0;
}

JS_PROTECTED void js_vm_store_resident_mac_key(js_vm_program *p, int mac_key) {
    if (!p) return;
    uint32_t mask = (uint32_t)js_vm_resident_key_mask(p);
    p->mac_key = (int)(((uint32_t)mac_key) ^ js_vbc4_rotl32_core(mask, 7));
}

JS_PROTECTED int js_vm_load_resident_mac_key(const js_vm_program *p) {
    if (!p) return 0;
    uint32_t mask = (uint32_t)js_vm_resident_key_mask(p);
    return (int)(((uint32_t)p->mac_key) ^ js_vbc4_rotl32_core(mask, 7));
}

JS_PROTECTED jint js_vm_resident_opcode_mask_epoch(const js_vm_program *p, int index, jint epoch) {
    uint32_t x = (uint32_t)js_vm_load_resident_mac_key(p) ^ (uint32_t)js_vm_load_resident_build_seed(p) ^ (uint32_t)(index * 0x45D9F3Bu);
    x ^= (uint32_t)epoch * 0x9E3779B1u;
    x ^= p ? js_vbc4_rotl32_core(p->resident_rotation_epoch, (index + 11) & 31) : 0u;
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    return (jint)(x & 0xFFu);
}

JS_PROTECTED jint js_vm_resident_opcode_mask(const js_vm_program *p, int index) {
    return js_vm_resident_opcode_mask_epoch(p, index, p && index >= 0 && index < p->insn_count ? p->insns[index].opcode_epoch : 0);
}

JS_PROTECTED jint js_vm_store_resident_opcode(const js_vm_program *p, int index, jint opcode) {
    return opcode ^ js_vm_resident_opcode_mask(p, index);
}

JS_PROTECTED jint js_vm_load_resident_opcode(const js_vm_program *p, int index) {
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

/* Inject trace poison into epoch/mask rotation: when debugger detected,
 * epoch/mask derivation becomes unstable across runs, making dump->replay fail. */
static uint32_t js_vm_poison_epoch_seed(uint32_t seed, uint32_t trace_state) {
    if (trace_state == 0 || js_vm_trace_poison_seed == 0) return seed;
    uint32_t poison = trace_state ^ js_vm_trace_poison_seed;
    poison ^= poison >> 13;
    poison *= 0x5BD1E995u;
    return seed ^ poison;
}
JS_HIDDEN void js_vm_rewrap_resident_opcode(js_vm_program *p, int index, jint opcode, int step, int pc_after_fetch, int stack_depth) {
    if (!p || index < 0 || index >= p->insn_count) return;
    jint next_epoch = js_vm_next_opcode_epoch(p, index, p->insns[index].opcode_epoch, step, pc_after_fetch, stack_depth);
    /* Poison epoch when trace detected: makes rewrapped opcodes diverge from clean dump */
    if (js_vm_trace_poison_seed != 0) {
        uint32_t poison_mix = js_vm_trace_poison_seed ^ (uint32_t)step ^ (uint32_t)index;
        next_epoch ^= (jint)(poison_mix & 0xFFu);
    }
    p->insns[index].opcode_epoch = next_epoch;
    p->insns[index].opcode = opcode ^ js_vm_resident_opcode_mask(p, index);
}

JS_HIDDEN void js_vm_rotate_resident_block(js_vm_program *p, int anchor, int step, uint32_t dispatch_drift_state, int pc_after_fetch, int stack_depth) {
    if (!p || p->insn_count <= 1) return;
    uint32_t seed = (uint32_t)js_vm_load_resident_build_seed(p) ^ (uint32_t)js_vm_load_resident_mac_key(p) ^ dispatch_drift_state;
    seed ^= (uint32_t)(step * 0x9E3779B1u) ^ (uint32_t)(pc_after_fetch * 0x85EBCA77u) ^ (uint32_t)(stack_depth * 0xC2B2AE3Du);
    /* Poison rotation seed when debugger detected: cache epoch becomes unstable */
    if (js_vm_trace_poison_seed != 0) {
        seed = js_vm_poison_epoch_seed(seed, js_vm_trace_poison_seed);
    }
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

JS_PROTECTED jint js_vm_resident_operand_mask(const js_vm_program *p, int insn_index, int operand_index) {
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

JS_PROTECTED jint js_vm_store_resident_operand(const js_vm_program *p, int insn_index, int operand_index, jint operand) {
    return operand ^ js_vm_resident_operand_mask(p, insn_index, operand_index);
}

JS_PROTECTED jint js_vm_load_resident_operand(const js_vm_program *p, int insn_index, int operand_index) {
    if (!p || insn_index < 0 || insn_index >= p->insn_count) return 0;
    if (operand_index < 0 || operand_index >= p->insns[insn_index].op_count || !p->insns[insn_index].ops) return 0;
    return p->insns[insn_index].ops[operand_index] ^ js_vm_resident_operand_mask(p, insn_index, operand_index);
}

#if defined(JS_NATIVE_CFG_EVIDENCE)
JS_EXPORT
#endif
JS_PROTECTED jint js_vm_profile_fetch_operand(const js_vm_program *p, uint32_t profile, int insn_index, int operand_index, uint32_t drift, int step, int sp) {
    if (!p || insn_index < 0 || insn_index >= p->insn_count) return 0;
    if (operand_index < 0 || operand_index >= p->insns[insn_index].op_count || !p->insns[insn_index].ops) return 0;
    uint32_t guard = drift ^ (uint32_t)(step * 0x9E3779B1u) ^ (uint32_t)(sp * 0x45D9F3Bu) ^ profile;
#if JS_NATIVE_OPERAND_PROFILE == 0
    int physical_operand = operand_index ^ (int)(guard & 0u);
    return js_vm_load_resident_operand(p, insn_index, physical_operand);
#elif JS_NATIVE_OPERAND_PROFILE == 1
    {
        jint stored = p->insns[insn_index].ops[operand_index];
        jint mask = js_vm_resident_operand_mask(p, insn_index, operand_index);
        return (stored ^ (jint)(guard & 0u)) ^ mask;
    }
#elif JS_NATIVE_OPERAND_PROFILE == 2
    {
        volatile jint value = p->insns[insn_index].ops[operand_index];
        value ^= js_vm_resident_operand_mask(p, insn_index, operand_index);
        return value;
    }
#else
#error "JS_NATIVE_OPERAND_PROFILE must be 0, 1 or 2"
#endif
}

JS_PROTECTED jint js_vm_resident_exception_mask(const js_vm_program *p, int exception_index, int field_index) {
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

JS_PROTECTED jint js_vm_store_resident_exception_field(const js_vm_program *p, int exception_index, int field_index, jint value) {
    return value ^ js_vm_resident_exception_mask(p, exception_index, field_index);
}

JS_PROTECTED jint js_vm_load_resident_exception_field(const js_vm_program *p, int exception_index, int field_index, jint value) {
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
    if (p->argument_tags) { js_vbc4_wipe_volatile(p->argument_tags, (size_t)p->argument_count + 1u); free(p->argument_tags); }
    if (p->resource_path) { js_vbc4_wipe_volatile(p->resource_path, strlen(p->resource_path)); free(p->resource_path); }
    if (p->reg_program.insns) {
        js_vbc4_wipe_volatile(p->reg_program.insns, (size_t)p->reg_program.insn_count * sizeof(js_vm_reg_insn));
        free(p->reg_program.insns);
    }
    if (p->insns) {
        if (!p->borrowed_insn_operands) {
            for (int i = 0; i < p->insn_count; i++) { if (p->insns[i].ops) { js_vbc4_wipe_volatile(p->insns[i].ops, (size_t)p->insns[i].op_count * sizeof(jint)); } free(p->insns[i].ops); }
        }
        if (!p->borrowed_insns) {
            js_vbc4_wipe_volatile(p->insns, (size_t)p->insn_count * sizeof(js_vm_insn));
            free(p->insns);
        }
    }
    if (p->exceptions && !p->borrowed_exceptions) { js_vbc4_wipe_volatile(p->exceptions, (size_t)p->exception_count * sizeof(js_vm_exception)); free(p->exceptions); }
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
/* ---- Native critical-region pre-decrypt protection ----
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
/* The max shell manual-maps inner native images outside the platform loader's
 * normal TLS bookkeeping. Keep these small VM runtime caches process-static on
 * Windows and GNU/Clang targets so the manually mapped inner image does not
 * dereference loader-managed static TLS slots from hot JNI callbacks. */
#if defined(_WIN32)
#define JS_THREAD_LOCAL
#elif defined(__GNUC__) || defined(__clang__)
#define JS_THREAD_LOCAL
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
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
    uint64_t token;
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

/* ---- Shared VM dispatcher-state pool ----
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
static void js_write_be32_tmp(unsigned char out[4], uint32_t value);
static uint32_t js_vm_entry_integrity_state(void);
static void js_vm_write_entry_integrity_bytes(unsigned char out[4]);
static void js_vm_write_clean_entry_integrity_bytes(unsigned char out[4]);
static void js_vbc4_copy_scoped_master_key(unsigned char out[32]);
static void js_vbc4_copy_scoped_layout_digest(unsigned char out[32]);
static void js_vbc4_session_integrity_material(unsigned char out[32]);
static void js_vbc4_hmac_with_scoped_master_key(const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]);
static void js_vbc4_vm_build_key(unsigned char out[32]);

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
#define JS_VM_LDC_CONDY 0xFC
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
#define JS_VM_REG_FLAG_SEMANTIC_SPLIT 0x0008
#define JS_VM_REG_FLAG_SEMANTIC_SHARE 0x4000
#define JS_VM_REG_FLAG_CONTINUATION 0x8000
#define JS_VM_REG_SEMANTIC_SHARE 0xF7
#define JS_VM_SUPER_CONST 0xF8
#define JS_VM_SUPER_INT_ARITH 0xF9
#define JS_VM_SUPER_CMP_BRANCH 0xFA
#define JS_VM_SUPER_INVOKE 0xFB
#define JS_VM_SUPER_BASE 0xF8
#define JS_VBC4_FLAG_ZSTD_SECTIONS 0x0400u
#define JS_VBC4_FLAG_BLOCK_DISPATCH 0x0800u
#define JS_VBC4_REQUIRED_FLAGS 0x0FFFu
#define JS_VBC4_FLAG_NESTED_VM 0x1000u
#define JS_VBC4_FLAG_POLYMORPHIC_CP 0x2000u
#define JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE 0x4000u
#define JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE 0x8000u
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
#define JS_RRK_RESOURCE_SLOTS 16
#define JS_RRK_ANCHOR_SLOT 16
#define JS_RRK_SLOTS 17
/* All sensitive build material is installed from one authenticated Java boot
 * envelope.  Only process-local XOR shares live here; the generated native
 * image contains no master/layout/partition bytes in .rodata. */
static unsigned char js_runtime_resource_key_shares[JS_RRK_SLOTS][JS_RRK_SHARE_COUNT][32];
static volatile int js_runtime_resource_key_slot_ready[JS_RRK_SLOTS];
static unsigned char js_runtime_master_key_shares[JS_RRK_SHARE_COUNT][32];
static unsigned char js_runtime_layout_digest_shares[JS_RRK_SHARE_COUNT][32];
static volatile int js_runtime_boot_material_state = 0;
static volatile int js_runtime_resource_partition_count = 0;
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
#if defined(JS_NATIVE_CFG_EVIDENCE)
JS_EXPORT
#endif
JS_PROTECTED int js_vm_parse_program(const unsigned char *data, int len, js_vm_program *p, const unsigned char *state_binding, int state_binding_len);
JS_PROTECTED unsigned char* js_runtime_resource_decode_owned(const unsigned char *raw, int raw_len, int *out_len);
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

static int js_vm_opcode_target_operand(jint opcode, int operand_index) {
    opcode = js_vm_canonical_opcode(opcode);
    switch (opcode) {
        case JS_VM_GOTO: case JS_VM_JSR:
        case JS_VM_IFEQ: case JS_VM_IFNE: case JS_VM_IFLT: case JS_VM_IFGE: case JS_VM_IFGT: case JS_VM_IFLE:
        case JS_VM_IF_ICMPEQ: case JS_VM_IF_ICMPNE: case JS_VM_IF_ICMPLT: case JS_VM_IF_ICMPGE:
        case JS_VM_IF_ICMPGT: case JS_VM_IF_ICMPLE: case JS_VM_IF_ACMPEQ: case JS_VM_IF_ACMPNE:
        case JS_VM_IFNULL: case JS_VM_IFNONNULL: return operand_index == 0;
        case JS_VM_TABLESWITCH: return operand_index == 2 || operand_index >= 3;
        case JS_VM_LOOKUPSWITCH: return operand_index == 1 || (operand_index >= 3 && (operand_index & 1) != 0);
        default: return 0;
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
    for (int i = 0; i < 32; i += 4) {
        uint32_t word = ((uint32_t)p->method_identity[i] << 24) | ((uint32_t)p->method_identity[i + 1] << 16) |
            ((uint32_t)p->method_identity[i + 2] << 8) | (uint32_t)p->method_identity[i + 3];
        x ^= js_vbc4_rotl32(word, (i + 7) & 31);
    }
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

static uint32_t js_vbc4_semantic_share_checksum(
    uint32_t seed,
    uint32_t logical_index,
    uint32_t opcode_share,
    uint32_t source_share,
    uint32_t operand_share) {
    uint32_t mixed = seed ^ (logical_index * 0x045D9F3Bu) ^
        (opcode_share * 0x7FEB352Du) ^ (source_share * 0x27D4EB2Du) ^ operand_share;
    mixed ^= mixed >> 16;
    mixed *= 0x7FEB352Du;
    mixed ^= mixed >> 13;
    mixed *= 0x846CA68Bu;
    return (mixed ^ (mixed >> 16)) & 0xFFFFu;
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

#if JS_NATIVE_PARSER_PROFILE != 0
static uint32_t js_vbc4_register_row_mix(uint32_t seed, uint32_t block_id, uint32_t row_index, uint32_t slot, uint32_t field_index) {
    uint32_t x = seed ^ (block_id * 0x045D9F3Bu) ^ (row_index * 0x7FEB352Du) ^
        (slot * 0x846CA68Bu) ^ (field_index * 0x2C1B3C6Du);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 13;
    x *= 0x846CA68Bu;
    return x ^ (x >> 16);
}

static void js_vbc4_register_row_order(uint32_t seed, uint32_t block_id, uint32_t row_index, int order[6]) {
    for (int i = 0; i < 6; i++) order[i] = i;
    for (int i = 5; i >= 0; i--) {
        int j = (int)(js_vbc4_register_row_mix(seed, block_id, row_index, (uint32_t)i, 0x71u) % (uint32_t)(i + 1));
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
}

static int js_vbc4_read_register_row(const unsigned char *data, int len, int *pos, uint32_t seed, uint32_t block_id, uint32_t row_index, unsigned int fields[6]) {
    int order[6];
    memset(fields, 0, sizeof(unsigned int) * 6u);
    js_vbc4_register_row_order(seed, block_id, row_index, order);
    for (int slot = 0; slot < 6; slot++) {
        int field = order[slot];
        unsigned int value16 = 0;
        uint32_t value32 = 0;
        uint32_t mask = js_vbc4_register_row_mix(seed, block_id, row_index, (uint32_t)slot, (uint32_t)field);
        if (field == 5) {
            if (!js_vm_read_u4(data, len, pos, &value32)) return 0;
            fields[field] = value32 ^ mask;
        } else {
            if (!js_vm_read_u2(data, len, pos, &value16)) return 0;
            fields[field] = (value16 ^ mask) & 0xFFFFu;
        }
    }
    return 1;
}

#if JS_NATIVE_PARSER_PROFILE == 2
static uint32_t js_vbc4_mixed_row_token(uint32_t seed, uint32_t block_id, uint32_t row_index, uint32_t shape) {
    uint32_t payload = (js_vbc4_register_row_mix(seed, block_id, row_index, shape, 0x5Eu) ^
        (shape * 0x045D9F3Bu)) & 0x3FFFu;
    return ((shape & 0x3u) << 14) | payload;
}

static int js_vbc4_read_mixed_operand_row(const unsigned char *data, int len, int *pos, uint32_t seed, uint32_t block_id, uint32_t row_index, unsigned int fields[6]) {
    unsigned int token = 0;
    memset(fields, 0, sizeof(unsigned int) * 6u);
    if (!js_vm_read_u2(data, len, pos, &token)) return 0;
    uint32_t shape = (token >> 14) & 0x3u;
    if (shape >= 3u || token != js_vbc4_mixed_row_token(seed, block_id, row_index, shape)) return 0;
    if (shape == 0u) {
        unsigned int raw_opcode = 0, flags = 0, dst = 0, srcA = 0, srcB = 0;
        uint32_t operand = 0;
        if (!js_vm_read_u2(data, len, pos, &raw_opcode)) return 0;
        if (!js_vm_read_u2(data, len, pos, &flags)) return 0;
        if (!js_vm_read_u2(data, len, pos, &dst)) return 0;
        if (!js_vm_read_u2(data, len, pos, &srcA)) return 0;
        if (!js_vm_read_u2(data, len, pos, &srcB)) return 0;
        if (!js_vm_read_u4(data, len, pos, &operand)) return 0;
        fields[0] = raw_opcode; fields[1] = flags; fields[2] = dst; fields[3] = srcA; fields[4] = srcB; fields[5] = operand;
        return 1;
    }
    if (shape == 1u) return js_vbc4_read_register_row(data, len, pos, seed, block_id, row_index, fields);
    uint32_t operand = 0;
    unsigned int srcB = 0, srcA = 0, dst = 0, flags = 0, raw_opcode = 0;
    if (!js_vm_read_u4(data, len, pos, &operand)) return 0;
    if (!js_vm_read_u2(data, len, pos, &srcB)) return 0;
    if (!js_vm_read_u2(data, len, pos, &srcA)) return 0;
    if (!js_vm_read_u2(data, len, pos, &dst)) return 0;
    if (!js_vm_read_u2(data, len, pos, &flags)) return 0;
    if (!js_vm_read_u2(data, len, pos, &raw_opcode)) return 0;
    fields[5] = operand ^ js_vbc4_register_row_mix(seed, block_id, row_index, 0x42u, 5u);
    fields[4] = (srcB ^ js_vbc4_register_row_mix(seed, block_id, row_index, 0x43u, 4u)) & 0xFFFFu;
    fields[3] = (srcA ^ js_vbc4_register_row_mix(seed, block_id, row_index, 0x44u, 3u)) & 0xFFFFu;
    fields[2] = (dst ^ js_vbc4_register_row_mix(seed, block_id, row_index, 0x45u, 2u)) & 0xFFFFu;
    fields[1] = (flags ^ js_vbc4_register_row_mix(seed, block_id, row_index, 0x46u, 1u)) & 0xFFFFu;
    fields[0] = (raw_opcode ^ js_vbc4_register_row_mix(seed, block_id, row_index, 0x47u, 0u)) & 0xFFFFu;
    return 1;
}
#endif
#endif

static uint32_t js_vbc4_native_row_dialect(uint32_t seed, uint32_t block_id, uint32_t row_count) {
#if JS_NATIVE_PARSER_PROFILE == 0
    (void)seed; (void)block_id; (void)row_count;
    return 0u;
#elif JS_NATIVE_PARSER_PROFILE == 1
    return js_vbc4_register_row_mix(seed, block_id, row_count, 0x23u, 0x4Du);
#else
    return js_vbc4_register_row_mix(seed, block_id, row_count, 0x23u, 0x4Du) ^
        js_vbc4_register_row_mix(seed, block_id, row_count, 0x61u, 0x4Fu);
#endif
}

static int js_vbc4_read_native_row(const unsigned char *data, int len, int *pos, uint32_t seed, uint32_t block_id, uint32_t row_index, unsigned int fields[6]) {
#if JS_NATIVE_PARSER_PROFILE == 0
    (void)data; (void)len; (void)pos; (void)seed; (void)block_id; (void)row_index; (void)fields;
    return 0;
#elif JS_NATIVE_PARSER_PROFILE == 1
    return js_vbc4_read_register_row(data, len, pos, seed, block_id, row_index, fields);
#else
    return js_vbc4_read_mixed_operand_row(data, len, pos, seed, block_id, row_index, fields);
#endif
}

static int js_vbc4_native_parser_profile_matches(uint32_t flags) {
    if ((flags & JS_VBC4_FLAG_NESTED_VM) != 0u) return 1;
#if JS_NATIVE_PARSER_PROFILE == 0
    return (flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0u;
#elif JS_NATIVE_PARSER_PROFILE == 1
    return (flags & JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE) != 0u && (flags & JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE) == 0u;
#elif JS_NATIVE_PARSER_PROFILE == 2
    return (flags & JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE) != 0u && (flags & JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE) == 0u;
#else
#error "JS_NATIVE_PARSER_PROFILE must be 0, 1 or 2"
#endif
}

static int js_vbc4_row_envelopes_mutually_exclusive(uint32_t flags) {
    uint32_t row_modes = 0;
    if ((flags & JS_VBC4_FLAG_NESTED_VM) != 0u) row_modes++;
    if ((flags & JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE) != 0u) row_modes++;
    if ((flags & JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE) != 0u) row_modes++;
    return row_modes <= 1u;
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

#ifndef JS_VBC4_RUNTIME_BOOT_MATERIAL
#error "VBC4 runtime boot-material mode must be generated into native_secrets.inc"
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

/*
 * AKEN v4 keeps the inner VBC4 grammar deterministic with public domain
 * material after its per-page evaluator has authenticated and opened a page.
 * These are not a boot key, build root, DEK, or runtime secret; deriving them
 * from labels prevents the native artifact from carrying contiguous key-like
 * byte arrays and removes VBC4's dependency on BootMaterialEnvelope state.
 */
static void js_aken_vbc4_copy_public_domain_material(
    const unsigned char *label,
    int label_len,
    unsigned char out[32]
) {
    js_sha256_ctx ctx;
    if (!out) return;
    memset(&ctx, 0, sizeof(ctx));
    js_sha256_init(&ctx);
    if (label && label_len > 0) js_sha256_update(&ctx, label, label_len);
    js_sha256_final(&ctx, out);
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
}

/* VBC4 compatibility material is reconstructed only into a scoped caller buffer. */
static void js_vbc4_copy_scoped_master_key(unsigned char out[32]) {
    static const unsigned char label[] =
        "javashroud-aken-v4-vbc4-inner-crypto-public-v1";
    js_aken_vbc4_copy_public_domain_material(
        label,
        (int)(sizeof(label) - 1u),
        out);
}

static void js_vbc4_copy_scoped_layout_digest(unsigned char out[32]) {
    static const unsigned char label[] =
        "javashroud-aken-v4-vbc4-inner-state-binding-public-v1";
    js_aken_vbc4_copy_public_domain_material(
        label,
        (int)(sizeof(label) - 1u),
        out);
}

JS_PROTECTED void js_hmac_sha256_with_key(const unsigned char *key, int key_len, const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]) {
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
    js_vbc4_copy_scoped_layout_digest(layout_digest);
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

/* Runtime-only VM key hierarchy. Stored VBC4 authentication continues to use
 * js_vbc4_hmac_with_scoped_master_key above, so a fresh startup nonce never
 * invalidates deterministic on-disk MACs. */
static const unsigned char JS_VM_BUILD_KEY_DOMAIN[] = "javashroud-vbc4-vm-build-key-v1";
static const unsigned char JS_VM_METHOD_KEY_DOMAIN[] = "javashroud-vbc4-vm-method-key-v1";
static const unsigned char JS_VM_SESSION_KEY_DOMAIN[] = "javashroud-vbc4-vm-session-key-v1";
static const unsigned char JS_VM_SESSION_TAG_DOMAIN[] = "javashroud-vbc4-vm-session-tag-v1";
static unsigned char js_vm_startup_nonce[32];
static volatile int js_vm_startup_nonce_ready = 0;

static void js_vbc4_vm_build_key(unsigned char out[32]) {
    unsigned char base_key[32];
    unsigned char layout_digest[32];
    js_vbc4_copy_scoped_master_key(base_key);
    js_vbc4_copy_scoped_layout_digest(layout_digest);
    const unsigned char *extract_parts[1] = { base_key };
    const int extract_lens[1] = { 32 };
    unsigned char prk[32];
    js_hmac_sha256_with_key(JS_VM_BUILD_KEY_DOMAIN, (int)(sizeof(JS_VM_BUILD_KEY_DOMAIN) - 1), extract_parts, extract_lens, 1, prk);
    unsigned char counter = 1;
    const unsigned char *expand_parts[2] = { layout_digest, &counter };
    const int expand_lens[2] = { 32, 1 };
    js_hmac_sha256_with_key(prk, 32, expand_parts, expand_lens, 2, out);
    js_vbc4_wipe_volatile(base_key, sizeof(base_key));
    js_vbc4_wipe_volatile(layout_digest, sizeof(layout_digest));
    js_vbc4_wipe_volatile(prk, sizeof(prk));
}

JS_HIDDEN int js_vm_copy_runtime_build_key(unsigned char out[32]) {
    if (!out) return 0;
    js_vbc4_vm_build_key(out);
    return 1;
}

static void js_vm_write_be64_tmp(unsigned char out[8], uint64_t value) {
    for (int i = 0; i < 8; i++) out[i] = (unsigned char)(value >> (56 - i * 8));
}

static int js_vm_runtime_session_leaf(
    jlong entry_token,
    const char *resource_path,
    const unsigned char method_nonce[16],
    unsigned char out[32]
) {
    if (!js_vm_startup_nonce_ready || entry_token == 0 || !resource_path || !resource_path[0] || !method_nonce || !out) return 0;
    unsigned char build_key[32], method_prk[32], method_key[32], session_prk[32], token_bytes[8];
    unsigned char counter = 1;
    js_vbc4_vm_build_key(build_key);
    js_vm_write_be64_tmp(token_bytes, (uint64_t)entry_token);
    const unsigned char *method_extract_parts[1] = { build_key };
    const int method_extract_lens[1] = { 32 };
    js_hmac_sha256_with_key(JS_VM_METHOD_KEY_DOMAIN, (int)(sizeof(JS_VM_METHOD_KEY_DOMAIN) - 1), method_extract_parts, method_extract_lens, 1, method_prk);
    const unsigned char *method_expand_parts[4] = { token_bytes, (const unsigned char*)resource_path, method_nonce, &counter };
    const int method_expand_lens[4] = { 8, (int)strlen(resource_path), 16, 1 };
    js_hmac_sha256_with_key(method_prk, 32, method_expand_parts, method_expand_lens, 4, method_key);
    const unsigned char *session_extract_parts[1] = { method_key };
    const int session_extract_lens[1] = { 32 };
    js_hmac_sha256_with_key(JS_VM_SESSION_KEY_DOMAIN, (int)(sizeof(JS_VM_SESSION_KEY_DOMAIN) - 1), session_extract_parts, session_extract_lens, 1, session_prk);
    counter = 1;
    const unsigned char *session_expand_parts[2] = { js_vm_startup_nonce, &counter };
    const int session_expand_lens[2] = { 32, 1 };
    js_hmac_sha256_with_key(session_prk, 32, session_expand_parts, session_expand_lens, 2, out);
    js_vbc4_wipe_volatile(build_key, sizeof(build_key));
    js_vbc4_wipe_volatile(method_prk, sizeof(method_prk));
    js_vbc4_wipe_volatile(method_key, sizeof(method_key));
    js_vbc4_wipe_volatile(session_prk, sizeof(session_prk));
    js_vbc4_wipe_volatile(token_bytes, sizeof(token_bytes));
    return 1;
}

static void js_vm_runtime_session_tag(const js_vm_program *program, const unsigned char leaf[32], unsigned char out[32]) {
    unsigned char token_bytes[8], profile_bytes[4], native_profile_bytes[4], dispatch_tag_bytes[4];
    unsigned char flags_bytes[4], nested_profile_bytes[4], call_flags_bytes[4], return_desc_byte[1];
    js_vm_write_be64_tmp(token_bytes, (uint64_t)program->entry_token);
    js_write_be32_tmp(profile_bytes, program->method_local_profile);
    js_write_be32_tmp(native_profile_bytes, program->native_vm_profile_id);
    js_write_be32_tmp(dispatch_tag_bytes, program->dispatch_profile_tag);
    js_write_be32_tmp(flags_bytes, program->vbc4_flags);
    js_write_be32_tmp(nested_profile_bytes, program->nested_vm_profile);
    js_write_be32_tmp(call_flags_bytes, program->is_static ? 1u : 0u);
    return_desc_byte[0] = (unsigned char)program->return_desc;
    /* All metadata fields that select identity, calling convention, or native
     * execution profile are immutable after bind and covered by this tag. */
    const unsigned char *parts[14] = {
        JS_VM_SESSION_TAG_DOMAIN, token_bytes, (const unsigned char*)program->resource_path,
        program->nonce, profile_bytes, native_profile_bytes, dispatch_tag_bytes, flags_bytes,
        nested_profile_bytes, call_flags_bytes, program->method_identity,
        program->owner_identity, (const unsigned char*)program->argument_tags,
        return_desc_byte
    };
    const int lens[14] = {
        (int)(sizeof(JS_VM_SESSION_TAG_DOMAIN) - 1), 8, (int)strlen(program->resource_path),
        16, 4, 4, 4, 4, 4, 4,
        32, 32, program->argument_tags ? program->argument_count : 0, 1
    };
    js_hmac_sha256_with_key(leaf, 32, parts, lens, 14, out);
    js_vbc4_wipe_volatile(token_bytes, sizeof(token_bytes));
    js_vbc4_wipe_volatile(profile_bytes, sizeof(profile_bytes));
    js_vbc4_wipe_volatile(native_profile_bytes, sizeof(native_profile_bytes));
    js_vbc4_wipe_volatile(dispatch_tag_bytes, sizeof(dispatch_tag_bytes));
    js_vbc4_wipe_volatile(flags_bytes, sizeof(flags_bytes));
    js_vbc4_wipe_volatile(nested_profile_bytes, sizeof(nested_profile_bytes));
    js_vbc4_wipe_volatile(call_flags_bytes, sizeof(call_flags_bytes));
    js_vbc4_wipe_volatile(return_desc_byte, sizeof(return_desc_byte));
}

JS_HIDDEN int js_vm_install_startup_nonce(const unsigned char *nonce, int nonce_len) {
    if (!nonce || nonce_len != 32 || js_vm_startup_nonce_ready) return 0;
    unsigned char nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= nonce[i];
    if (!nonzero) return 0;
    memcpy(js_vm_startup_nonce, nonce, 32);
    js_vm_startup_nonce_ready = 1;
    return 1;
}

JS_HIDDEN void js_vm_clear_startup_nonce(void) {
    js_vbc4_wipe_volatile(js_vm_startup_nonce, sizeof(js_vm_startup_nonce));
    js_vm_startup_nonce_ready = 0;
}

static void js_vm_abort_preload_state(JNIEnv *env) {
    js_vm_preload_in_progress = 0;
    js_vm_ephemeral_cache_clear(env);
    js_vm_call_gate_reset();
    js_vbc4_wipe_volatile((void*)js_vm_shared_dispatch_pool, sizeof(js_vm_shared_dispatch_pool));
    js_vm_shared_dispatch_epoch = 0;
    js_vm_shared_dispatch_seeded = 0;
    js_vm_clear_startup_nonce();
}

JS_HIDDEN int js_vm_bind_runtime_session(js_vm_program *program, jlong entry_token, const char *resource_path) {
    if (!program || !resource_path || !resource_path[0]) return 0;
    program->entry_token = entry_token;
    if (program->resource_path) { js_vbc4_wipe_volatile(program->resource_path, strlen(program->resource_path)); free(program->resource_path); }
    program->resource_path = js_strdup(resource_path);
    if (!program->resource_path || !js_vm_runtime_session_leaf(entry_token, resource_path, program->nonce, program->session_leaf)) return 0;
    js_vm_runtime_session_tag(program, program->session_leaf, program->session_tag);
    program->session_bound = 1;
    const char *session_evidence = getenv("JAVASHROUD_SESSION_EVIDENCE");
    if (session_evidence && session_evidence[0] == '1' && session_evidence[1] == 0) {
        fprintf(stderr, "JAVASHROUD_VM_SESSION=");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", program->session_tag[i]);
        fprintf(stderr, "\n");
    }
    return 1;
}

JS_HIDDEN int js_vm_verify_runtime_session(const js_vm_program *program) {
    if (!program || !program->session_bound || !program->resource_path) return 0;
    unsigned char expected_leaf[32], expected_tag[32];
    if (!js_vm_runtime_session_leaf(program->entry_token, program->resource_path, program->nonce, expected_leaf)) return 0;
    js_vm_runtime_session_tag(program, expected_leaf, expected_tag);
    unsigned char diff = 0;
    for (int i = 0; i < 32; i++) diff |= (unsigned char)(expected_leaf[i] ^ program->session_leaf[i]);
    for (int i = 0; i < 32; i++) diff |= (unsigned char)(expected_tag[i] ^ program->session_tag[i]);
    js_vbc4_wipe_volatile(expected_leaf, sizeof(expected_leaf));
    js_vbc4_wipe_volatile(expected_tag, sizeof(expected_tag));
    return diff == 0;
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

static void js_runtime_hmac_sha256(int slot, const unsigned char **parts, const int *part_lens, int part_count, unsigned char out[32]) {
    if (js_runtime_boot_material_state != 2 || slot < 0 || slot >= JS_RRK_SLOTS || !js_runtime_resource_key_slot_ready[slot]) { memset(out, 0, 32); return; }
    unsigned char root[32];
    js_rrk_xor_assemble(&js_runtime_resource_key_shares[slot][0][0], JS_RRK_SHARE_COUNT, root);
    js_hmac_sha256_with_key(root, 32, parts, part_lens, part_count, out);
    js_vbc4_wipe_volatile(root, sizeof(root));
}

static void js_runtime_resource_aes_ctr(int slot, unsigned char *buf, int len, const unsigned char nonce[16], int kind_id, int variant_id, int layer_count) {
    static const unsigned char key_label[] = "jsrp-aes-key";
    static const unsigned char iv_label[] = "jsrp-aes-iv";
    unsigned char kind_bytes[4], variant_bytes[4], layer_bytes[4], digest[32], key[16], counter[16], stream[16];
    js_write_be32_tmp(kind_bytes, (uint32_t)kind_id);
    js_write_be32_tmp(variant_bytes, (uint32_t)variant_id);
    js_write_be32_tmp(layer_bytes, (uint32_t)layer_count);
    const unsigned char *key_parts[5] = { key_label, nonce, kind_bytes, variant_bytes, layer_bytes };
    int key_lens[5] = { (int)(sizeof(key_label) - 1), 16, 4, 4, 4 };
    js_runtime_hmac_sha256(slot, key_parts, key_lens, 5, digest);
    memcpy(key, digest, 16);
    const unsigned char *iv_parts[5] = { iv_label, nonce, kind_bytes, variant_bytes, layer_bytes };
    int iv_lens[5] = { (int)(sizeof(iv_label) - 1), 16, 4, 4, 4 };
    js_runtime_hmac_sha256(slot, iv_parts, iv_lens, 5, digest);
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

JS_HIDDEN void js_runtime_sha256(const unsigned char *data, int len, unsigned char out[32]) {
    js_sha256_ctx ctx;
    js_sha256_init(&ctx);
    js_sha256_update(&ctx, data, len);
    js_sha256_final(&ctx, out);
}

static void js_runtime_resource_aes_ctr_domains(int slot, unsigned char *buf, int len, const unsigned char nonce[16], uint32_t kind_id, uint32_t variant_id, uint32_t layer_count) {
    int kind_arg = (int)kind_id;
    int variant_arg = (int)variant_id;
    int layer_arg = (int)layer_count;
    js_runtime_resource_aes_ctr(slot, buf, len, nonce, kind_arg, variant_arg, layer_arg);
}

static unsigned char* js_runtime_resource_decode_current_owned(const unsigned char *raw, int raw_len, int *out_len) {
    static const unsigned char auth_label[] = "jsrp-auth-v3";
    if (raw_len < 156 || raw[raw_len - 1] != 32) return NULL;
    const unsigned char *nonce = raw + 5;
    uint32_t metadata_len = js_read_le16_runtime(raw, 21);
    uint32_t mac_len = js_read_le16_runtime(raw, 23);
    uint32_t partition_id = js_read_le16_runtime(raw, 25);
    if (metadata_len != 96 || mac_len != 32) return NULL;
    if (partition_id > (uint32_t)js_runtime_resource_partition_count) return NULL;
    int key_slot = partition_id == (uint32_t)js_runtime_resource_partition_count ? JS_RRK_ANCHOR_SLOT : (int)partition_id;
    if (!js_runtime_resource_key_slot_ready[key_slot]) return NULL;
    int metadata_offset = 27;
    int body_offset = metadata_offset + (int)metadata_len;
    if (body_offset + 33 > raw_len) return NULL;
    int tag_offset = raw_len - 33;
    unsigned char expected[32];
    const unsigned char *parts[3] = { auth_label, nonce, raw };
    int lens[3] = { (int)(sizeof(auth_label) - 1), 16, tag_offset };
    js_runtime_hmac_sha256(key_slot, parts, lens, 3, expected);
    if (!js_runtime_resource_ct_equal(raw + tag_offset, expected, 32)) {
        js_vbc4_wipe_volatile(expected, sizeof(expected));
        return NULL;
    }
    js_vbc4_wipe_volatile(expected, sizeof(expected));

    unsigned char metadata[96];
    memcpy(metadata, raw + metadata_offset, sizeof(metadata));
    js_runtime_resource_aes_ctr_domains(key_slot, metadata, (int)sizeof(metadata), nonce, 0, 0, 0);
    if (metadata[0] != 0x4Du || metadata[1] != 0x32u || metadata[2] != 1u) {
        js_vbc4_wipe_volatile(metadata, sizeof(metadata));
        return NULL;
    }
    if ((uint32_t)(metadata[7] & 0xFFu) != partition_id) {
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
    js_runtime_resource_aes_ctr_domains(key_slot, stored, (int)body_len, nonce, kind_id, variant_id, layer_count);
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
    (void)raw; (void)raw_len; (void)out_len;
    /* Legacy pre-partition envelopes are rejected fail-closed. */
    return NULL;
}

JS_PROTECTED unsigned char* js_runtime_resource_decode_owned(const unsigned char *raw, int raw_len, int *out_len) {
    if (out_len) *out_len = 0;
    if (!raw || raw_len < 6) return NULL;
    if (raw[0] != 0x4A || raw[1] != 0x53 || raw[2] != 0x52 || raw[3] != 0x50) return NULL;
    if (raw[4] == 7) return js_runtime_resource_decode_current_owned(raw, raw_len, out_len);
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

/* Keyed environment token: HMAC-SHA256(anchorKey, "envk1" || material)[0..4]
 * as 8 lowercase hex chars. Mirrors the Kotlin build-time derivation; without
 * the resident anchor key the expected token cannot be recomputed statically. */
static int js_env_binding_token(const char *material, char out_hex[9]) {
    if (!material || !js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT]) return 0;
    static const unsigned char domain[] = "envk1";
    static const char hexdig[] = "0123456789abcdef";
    unsigned char root[32];
    unsigned char digest[32];
    const unsigned char *parts[2];
    int lens[2];
    parts[0] = domain;
    lens[0] = (int)(sizeof(domain) - 1);
    parts[1] = (const unsigned char*)material;
    lens[1] = (int)strlen(material);
    js_rrk_xor_assemble(&js_runtime_resource_key_shares[JS_RRK_ANCHOR_SLOT][0][0], JS_RRK_SHARE_COUNT, root);
    js_hmac_sha256_with_key(root, 32, parts, lens, 2, digest);
    js_vbc4_wipe_volatile(root, sizeof(root));
    for (int i = 0; i < 4; i++) {
        out_hex[i * 2] = hexdig[(digest[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hexdig[digest[i] & 0xF];
    }
    out_hex[8] = 0;
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return 1;
}

/* Constant-time equality for two NUL-terminated strings. Returns 1 if equal. */
static int js_consttime_str_equal(const char *a, const char *b) {
    if (!a || !b) return a == b;
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    if (len_a != len_b) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < len_a; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* Returns 1 if |machine_id| matches one of the comma-separated fingerprints in
 * |expected_list|. Comparison is constant-time per candidate. */
static int js_machine_id_matches(const char *machine_id, const char *expected_list) {
    if (!machine_id || !machine_id[0] || !expected_list || !expected_list[0]) return 0;
    const char *cursor = expected_list;
    while (*cursor) {
        const char *end = strchr(cursor, ',');
        size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
        while (len > 0 && (cursor[len - 1] == ' ' || cursor[len - 1] == '\t' || cursor[len - 1] == '\r' || cursor[len - 1] == '\n')) len--;
        size_t start = 0;
        while (start < len && (cursor[start] == ' ' || cursor[start] == '\t')) start++;
        if (len > start) {
            size_t cmp_len = len - start;
            if (strlen(machine_id) == cmp_len) {
                unsigned char diff = 0;
                for (size_t i = 0; i < cmp_len; i++) diff |= (unsigned char)(machine_id[i] ^ cursor[start + i]);
                if (diff == 0) return 1;
            }
        }
        if (!end) break;
        cursor = end + 1;
    }
    return 0;
}

/* Derive an environment token that includes a hardware fingerprint when
 * bindingSource is "hardware-id" and expectedFingerprint is supplied. */
static int js_env_binding_token_hardware(
    const char *binding_source,
    const char *salt,
    const char *expected_fingerprint,
    char out_hex[9]) {
    char km[384];
    char machine_id[128];
    int written;
    if (!binding_source || strcmp(binding_source, "hardware-id") != 0) {
        snprintf(km, sizeof(km), "envkey:%s:%s", binding_source ? binding_source : "", salt ? salt : "");
        int ok = js_env_binding_token(km, out_hex);
        js_vbc4_wipe_volatile(km, sizeof(km));
        return ok;
    }
    if (!expected_fingerprint || !expected_fingerprint[0]) {
        /* Backward-compatible path: no explicit fingerprint, derive from salt only. */
        snprintf(km, sizeof(km), "envkey:%s:%s", binding_source, salt ? salt : "");
        int ok = js_env_binding_token(km, out_hex);
        js_vbc4_wipe_volatile(km, sizeof(km));
        return ok;
    }
    written = js_machine_id(machine_id, sizeof(machine_id));
    if (written <= 0 || !js_machine_id_matches(machine_id, expected_fingerprint)) {
        js_vbc4_wipe_volatile(machine_id, sizeof(machine_id));
        return 0;
    }
    /* Build-time derivation used the full expectedFingerprint string, so the
     * runtime token must use the same material after confirming a match. */
    snprintf(km, sizeof(km), "envkey:%s:%s:%s", binding_source, salt ? salt : "", expected_fingerprint);
    js_vbc4_wipe_volatile(machine_id, sizeof(machine_id));
    int ok = js_env_binding_token(km, out_hex);
    js_vbc4_wipe_volatile(km, sizeof(km));
    return ok;
}

JS_LOCAL jstring JNICALL
jsn_r16(JNIEnv *env, jclass cls, jstring bindingSource, jstring salt, jstring expectedFingerprint) {
    (void)cls;
    const char *src = j2c(env, bindingSource);
    const char *slt = j2c(env, salt);
    const char *exp = j2c(env, expectedFingerprint);
    char hex[32];
    if (!js_env_binding_token_hardware(src, slt, exp, hex)) {
        rls(env, bindingSource, src);
        rls(env, salt, slt);
        rls(env, expectedFingerprint, exp);
        throw_sec(env, "environment binding key derivation requires installed boot material");
        return NULL;
    }
    rls(env, bindingSource, src);
    rls(env, salt, slt);
    rls(env, expectedFingerprint, exp);
    return (*env)->NewStringUTF(env, hex);
}

JS_LOCAL void JNICALL
jsn_r17(JNIEnv *env, jclass cls, jstring expectedToken, jstring bindingSource, jstring salt, jstring expectedFingerprint) {
    (void)cls;
    const char *tok = j2c(env, expectedToken);
    const char *src = j2c(env, bindingSource);
    const char *slt = j2c(env, salt);
    const char *exp = j2c(env, expectedFingerprint);
    if (tok && strlen(tok) > 0) {
        char hex[32];
        if (!js_env_binding_token_hardware(src, slt, exp, hex)) {
            rls(env, expectedToken, tok);
            rls(env, bindingSource, src);
            rls(env, salt, slt);
            rls(env, expectedFingerprint, exp);
            throw_sec(env, "environment binding verification failed");
            return;
        }
        if (!js_consttime_str_equal(tok, hex)) {
            rls(env, expectedToken, tok);
            rls(env, bindingSource, src);
            rls(env, salt, slt);
            rls(env, expectedFingerprint, exp);
            throw_sec(env, "Environment binding verification failed");
            return;
        }
    }
    rls(env, expectedToken, tok);
    rls(env, bindingSource, src);
    rls(env, salt, slt);
    rls(env, expectedFingerprint, exp);
}

JS_LOCAL jstring JNICALL
jsn_r18(JNIEnv *env, jclass cls) {
    (void)cls;
    char machine_id[128];
    int written = js_machine_id(machine_id, sizeof(machine_id));
    if (written <= 0) {
        throw_sec(env, "unable to collect machine fingerprint");
        return NULL;
    }
    return (*env)->NewStringUTF(env, machine_id);
}

static void js_string_root_material(unsigned char out[32]) {
    static const unsigned char domain[] = "javashroud-string-root-v1";
    unsigned char master_key[32], layout_digest[32], prk[32], counter = 1;
    js_vbc4_copy_scoped_master_key(master_key);
    js_vbc4_copy_scoped_layout_digest(layout_digest);
    const unsigned char *extract_parts[1] = { master_key };
    const int extract_lens[1] = { 32 };
    js_hmac_sha256_with_key(domain, (int)(sizeof(domain) - 1), extract_parts, extract_lens, 1, prk);
    const unsigned char *expand_parts[2] = { layout_digest, &counter };
    const int expand_lens[2] = { 32, 1 };
    js_hmac_sha256_with_key(prk, 32, expand_parts, expand_lens, 2, out);
    js_vbc4_wipe_volatile(master_key, sizeof(master_key));
    js_vbc4_wipe_volatile(layout_digest, sizeof(layout_digest));
    js_vbc4_wipe_volatile(prk, sizeof(prk));
}

static void js_string_class_material(const unsigned char class_identity[16], unsigned char out[32]) {
    static const unsigned char domain[] = "javashroud-string-class-v1";
    unsigned char string_root[32], prk[32], counter = 1;
    js_string_root_material(string_root);
    const unsigned char *extract_parts[1] = { string_root };
    const int extract_lens[1] = { 32 };
    js_hmac_sha256_with_key(domain, (int)(sizeof(domain) - 1), extract_parts, extract_lens, 1, prk);
    const unsigned char *expand_parts[2] = { class_identity, &counter };
    const int expand_lens[2] = { 16, 1 };
    js_hmac_sha256_with_key(prk, 32, expand_parts, expand_lens, 2, out);
    js_vbc4_wipe_volatile(string_root, sizeof(string_root));
    js_vbc4_wipe_volatile(prk, sizeof(prk));
}

static void js_string_payload_material(
    int seed,
    int flags,
    int len,
    uint64_t class_identity_high,
    uint64_t class_identity_low,
    unsigned char key[16],
    unsigned char iv[16]) {
    static const unsigned char key_label[] = "js-string-aes-key";
    static const unsigned char iv_label[] = "js-string-aes-iv";
    unsigned char seed_bytes[4], flags_bytes[4], len_bytes[4], class_identity[16], class_key[32], scoped_key[32], digest[32];
    js_write_be32_tmp(seed_bytes, (uint32_t)seed);
    js_write_be32_tmp(flags_bytes, (uint32_t)flags);
    js_write_be32_tmp(len_bytes, (uint32_t)len);
    js_vm_write_be64_tmp(class_identity, class_identity_high);
    js_vm_write_be64_tmp(class_identity + 8, class_identity_low);
    const unsigned char *key_parts[4] = { key_label, seed_bytes, flags_bytes, len_bytes };
    int key_lens[4] = { (int)(sizeof(key_label) - 1), 4, 4, 4 };
    js_string_class_material(class_identity, class_key);
    js_hmac_sha256_with_key(class_key, 32, key_parts, key_lens, 4, scoped_key);
    js_hmac_sha256_with_key(scoped_key, 32, key_parts, key_lens, 4, digest);
    memcpy(key, digest, 16);
    const unsigned char *iv_parts[4] = { iv_label, seed_bytes, flags_bytes, len_bytes };
    int iv_lens[4] = { (int)(sizeof(iv_label) - 1), 4, 4, 4 };
    js_hmac_sha256_with_key(class_key, 32, iv_parts, iv_lens, 4, scoped_key);
    js_hmac_sha256_with_key(scoped_key, 32, iv_parts, iv_lens, 4, digest);
    memcpy(iv, digest, 16);
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    js_vbc4_wipe_volatile(scoped_key, sizeof(scoped_key));
    js_vbc4_wipe_volatile(class_key, sizeof(class_key));
    js_vbc4_wipe_volatile(class_identity, sizeof(class_identity));
    js_vbc4_wipe_volatile(seed_bytes, sizeof(seed_bytes));
    js_vbc4_wipe_volatile(flags_bytes, sizeof(flags_bytes));
    js_vbc4_wipe_volatile(len_bytes, sizeof(len_bytes));
}

JS_LOCAL jbyteArray JNICALL
jsn_r21(JNIEnv *env, jclass cls, jbyteArray payload, jint seed, jint flags, jlong class_identity_high, jlong class_identity_low) {
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsn_r21, 1)) return NULL;
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
    js_string_payload_material(
        (int)seed,
        (int)flags,
        (int)len,
        (uint64_t)class_identity_high,
        (uint64_t)class_identity_low,
        key,
        counter);
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

/* Sensitive material must never cross a JNI boundary while a debugger,
 * trampoline, or known instrumentation marker is present. The VM hot loop keeps
 * its cached probe; these entries deliberately force a fresh probe each call. */
JS_HIDDEN int js_vm_sensitive_path_guard(JNIEnv *env, const void *entry, int clear_boot_material) {
    int permitted = entry && js_check_trampoline(entry) &&
        !js_vm_strong_debugger_present_now() && !js_detect_instrumentation();
    if (permitted) return 1;
    if (clear_boot_material) {
        js_runtime_boot_material_clear();
        js_runtime_boot_material_state = -1;
    }
    js_vm_throw_new(env, "java/lang/SecurityException", "native sensitive material path integrity failure");
    return 0;
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

#if defined(JS_NATIVE_CFG_EVIDENCE)
JS_EXPORT
#endif
JS_PROTECTED int js_vm_parse_program(const unsigned char *data, int len, js_vm_program *p, const unsigned char *state_binding, int state_binding_len) {
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
    p->native_vm_profile_id = 0;
    p->dispatch_profile_tag = 0;
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
    if (((unsigned int)vbc4_flags & (JS_VBC4_REQUIRED_FLAGS | JS_VBC4_FLAG_POLYMORPHIC_CP)) !=
        (JS_VBC4_REQUIRED_FLAGS | JS_VBC4_FLAG_POLYMORPHIC_CP)) JS_VM_PARSE_FAIL; /* require full VBC4 max-strength feature set */
    if (!js_vbc4_row_envelopes_mutually_exclusive((uint32_t)vbc4_flags)) JS_VM_PARSE_FAIL;
    if (!js_vbc4_native_parser_profile_matches((uint32_t)vbc4_flags)) JS_VM_PARSE_FAIL;
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
            uint32_t row_dialect = 0;
            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &register_count)) JS_VM_PARSE_FAIL;
            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &register_insn_count)) JS_VM_PARSE_FAIL;
            if ((vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) != 0 && (vbc4_flags & JS_VBC4_FLAG_NESTED_VM) == 0) {
                uint32_t expected_dialect = js_vbc4_native_row_dialect((uint32_t)build_seed, (uint32_t)bi, register_insn_count);
                if (!js_vm_read_u4(block, (int)block_plain_sz, &block_pos, &row_dialect)) JS_VM_PARSE_FAIL;
                if (row_dialect != expected_dialect) JS_VM_PARSE_FAIL;
            }
            p->reg_program.register_count = (int)register_count;
            int base_insn = p->insn_count;
            for (unsigned int ri = 0; ri < register_insn_count; ri++) {
                unsigned int raw_opcode = 0, flags = 0, op_count = 0, srcA = 0, srcB = 0;
                if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0 || (vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0) {
                    if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &raw_opcode)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &flags)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &op_count)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &srcA)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &srcB)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u4(block, (int)block_plain_sz, &block_pos, &u4)) JS_VM_PARSE_FAIL;
                } else {
                    unsigned int row_fields[6];
                    int row_ok = js_vbc4_read_native_row(block, (int)block_plain_sz, &block_pos, (uint32_t)build_seed, (uint32_t)bi, ri, row_fields);
                    if (!row_ok) JS_VM_PARSE_FAIL;
                    raw_opcode = row_fields[0];
                    flags = row_fields[1];
                    op_count = row_fields[2];
                    srcA = row_fields[3];
                    srcB = row_fields[4];
                    u4 = row_fields[5];
                }
                if ((flags & JS_VM_REG_FLAG_SEMANTIC_SHARE) != 0u) JS_VM_PARSE_FAIL;
                if ((flags & JS_VM_REG_FLAG_SEMANTIC_SPLIT) != 0u) {
                    unsigned int share_opcode = 0, share_flags = 0, share_opcode_mask = 0, share_source_mask = 0, share_checksum = 0, share_operand_mask = 0;
                    if ((flags & JS_VM_REG_FLAG_EXECUTABLE) == 0u || ++ri >= register_insn_count) JS_VM_PARSE_FAIL;
                    if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0 || (vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0) {
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &share_opcode)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &share_flags)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &share_opcode_mask)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &share_source_mask)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &share_checksum)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u4(block, (int)block_plain_sz, &block_pos, &share_operand_mask)) JS_VM_PARSE_FAIL;
                    } else {
                        unsigned int share_fields[6];
                        int share_ok = js_vbc4_read_native_row(block, (int)block_plain_sz, &block_pos, (uint32_t)build_seed, (uint32_t)bi, ri, share_fields);
                        if (!share_ok) JS_VM_PARSE_FAIL;
                        share_opcode = share_fields[0];
                        share_flags = share_fields[1];
                        share_opcode_mask = share_fields[2];
                        share_source_mask = share_fields[3];
                        share_checksum = share_fields[4];
                        share_operand_mask = share_fields[5];
                    }
                    if (share_opcode != JS_VM_REG_SEMANTIC_SHARE || share_flags != JS_VM_REG_FLAG_SEMANTIC_SHARE ||
                        share_checksum != js_vbc4_semantic_share_checksum((uint32_t)build_seed, (uint32_t)logical_insn_index, share_opcode_mask, share_source_mask, share_operand_mask)) JS_VM_PARSE_FAIL;
                    raw_opcode ^= share_opcode_mask;
                    srcA ^= share_source_mask;
                    u4 ^= share_operand_mask;
                    flags &= ~JS_VM_REG_FLAG_SEMANTIC_SPLIT;
                }
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
                        if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0 || (vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0) {
                            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_opcode)) JS_VM_PARSE_FAIL;
                            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_flags)) JS_VM_PARSE_FAIL;
                            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_dst)) JS_VM_PARSE_FAIL;
                            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_srcA)) JS_VM_PARSE_FAIL;
                            if (!js_vm_read_u2(block, (int)block_plain_sz, &block_pos, &cont_srcB)) JS_VM_PARSE_FAIL;
                            if (!js_vm_read_u4(block, (int)block_plain_sz, &block_pos, &cont_operand)) JS_VM_PARSE_FAIL;
                        } else {
                            unsigned int cont_fields[6];
                            int cont_ok = js_vbc4_read_native_row(block, (int)block_plain_sz, &block_pos, (uint32_t)build_seed, (uint32_t)bi, ri, cont_fields);
                            if (!cont_ok) JS_VM_PARSE_FAIL;
                            cont_opcode = cont_fields[0];
                            cont_flags = cont_fields[1];
                            cont_dst = cont_fields[2];
                            cont_srcA = cont_fields[3];
                            cont_srcB = cont_fields[4];
                            cont_operand = cont_fields[5];
                        }
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
            if (block_pos != (int)block_plain_sz) JS_VM_PARSE_FAIL;
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
        uint32_t row_dialect = 0;
        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &register_count)) JS_VM_PARSE_FAIL;
        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &register_insn_count)) JS_VM_PARSE_FAIL;
        if ((vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) != 0 && (vbc4_flags & JS_VBC4_FLAG_NESTED_VM) == 0) {
            uint32_t expected_dialect = js_vbc4_native_row_dialect((uint32_t)build_seed, (uint32_t)block_ids[0], register_insn_count);
            if (!js_vm_read_u4(insn, (int)insn_plain_sz, &insn_pos, &row_dialect)) JS_VM_PARSE_FAIL;
            if (row_dialect != expected_dialect) JS_VM_PARSE_FAIL;
        }
        p->reg_program.register_count = (int)register_count;
        int logical_insn_index = 0;
        for (unsigned int ri = 0; ri < register_insn_count; ri++) {
            unsigned int raw_opcode = 0, flags = 0, op_count = 0, srcA = 0, srcB = 0;
            if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0 || (vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0) {
                if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &raw_opcode)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &flags)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &op_count)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &srcA)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &srcB)) JS_VM_PARSE_FAIL;
                if (!js_vm_read_u4(insn, (int)insn_plain_sz, &insn_pos, &u4)) JS_VM_PARSE_FAIL;
            } else {
                unsigned int row_fields[6];
                int row_ok = js_vbc4_read_native_row(insn, (int)insn_plain_sz, &insn_pos, (uint32_t)build_seed, (uint32_t)block_ids[0], ri, row_fields);
                if (!row_ok) JS_VM_PARSE_FAIL;
                raw_opcode = row_fields[0];
                flags = row_fields[1];
                op_count = row_fields[2];
                srcA = row_fields[3];
                srcB = row_fields[4];
                u4 = row_fields[5];
            }
            if ((flags & JS_VM_REG_FLAG_SEMANTIC_SHARE) != 0u) JS_VM_PARSE_FAIL;
            if ((flags & JS_VM_REG_FLAG_SEMANTIC_SPLIT) != 0u) {
                unsigned int share_opcode = 0, share_flags = 0, share_opcode_mask = 0, share_source_mask = 0, share_checksum = 0, share_operand_mask = 0;
                if ((flags & JS_VM_REG_FLAG_EXECUTABLE) == 0u || ++ri >= register_insn_count) JS_VM_PARSE_FAIL;
                if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0 || (vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0) {
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &share_opcode)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &share_flags)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &share_opcode_mask)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &share_source_mask)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &share_checksum)) JS_VM_PARSE_FAIL;
                    if (!js_vm_read_u4(insn, (int)insn_plain_sz, &insn_pos, &share_operand_mask)) JS_VM_PARSE_FAIL;
                } else {
                    unsigned int share_fields[6];
                    int share_ok = js_vbc4_read_native_row(insn, (int)insn_plain_sz, &insn_pos, (uint32_t)build_seed, (uint32_t)block_ids[0], ri, share_fields);
                    if (!share_ok) JS_VM_PARSE_FAIL;
                    share_opcode = share_fields[0];
                    share_flags = share_fields[1];
                    share_opcode_mask = share_fields[2];
                    share_source_mask = share_fields[3];
                    share_checksum = share_fields[4];
                    share_operand_mask = share_fields[5];
                }
                if (share_opcode != JS_VM_REG_SEMANTIC_SHARE || share_flags != JS_VM_REG_FLAG_SEMANTIC_SHARE ||
                    share_checksum != js_vbc4_semantic_share_checksum((uint32_t)build_seed, (uint32_t)logical_insn_index, share_opcode_mask, share_source_mask, share_operand_mask)) JS_VM_PARSE_FAIL;
                raw_opcode ^= share_opcode_mask;
                srcA ^= share_source_mask;
                u4 ^= share_operand_mask;
                flags &= ~JS_VM_REG_FLAG_SEMANTIC_SPLIT;
            }
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
                    if ((vbc4_flags & JS_VBC4_FLAG_NESTED_VM) != 0 || (vbc4_flags & (JS_VBC4_FLAG_REGISTER_ROW_ENVELOPE | JS_VBC4_FLAG_MIXED_OPERAND_ENVELOPE)) == 0) {
                        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_opcode)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_flags)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_dst)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_srcA)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u2(insn, (int)insn_plain_sz, &insn_pos, &cont_srcB)) JS_VM_PARSE_FAIL;
                        if (!js_vm_read_u4(insn, (int)insn_plain_sz, &insn_pos, &cont_operand)) JS_VM_PARSE_FAIL;
                    } else {
                        unsigned int cont_fields[6];
                        int cont_ok = js_vbc4_read_native_row(insn, (int)insn_plain_sz, &insn_pos, (uint32_t)build_seed, (uint32_t)block_ids[0], ri, cont_fields);
                        if (!cont_ok) JS_VM_PARSE_FAIL;
                        cont_opcode = cont_fields[0];
                        cont_flags = cont_fields[1];
                        cont_dst = cont_fields[2];
                        cont_srcA = cont_fields[3];
                        cont_srcB = cont_fields[4];
                        cont_operand = cont_fields[5];
                    }
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
        if (insn_pos != (int)insn_plain_sz) JS_VM_PARSE_FAIL;
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
    if (!p || p->entry_token == 0) return 0;
    if (js_vm_guest_frame_count >= max_count) return 0;
    js_vm_guest_frames[js_vm_guest_frame_count].token = (uint64_t)p->entry_token;
    js_vm_guest_frame_count++;
    return 1;
}
static void js_vm_guest_frame_restore(int saved_count, int pushed) {
    int max_count = (int)(sizeof(js_vm_guest_frames) / sizeof(js_vm_guest_frames[0]));
    if (saved_count < 0) saved_count = 0;
    if (saved_count > max_count) saved_count = max_count;
    if (pushed) {
        for (int i = saved_count; i < js_vm_guest_frame_count && i < max_count; i++) {
            js_vm_guest_frames[i].token = 0;
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
        char method_name[32];
        snprintf(method_name, sizeof(method_name), "m_%016llx", (unsigned long long)frame->token);
        jstring cls = (*env)->NewStringUTF(env, "javashroud.vbc4.Guest");
        jstring name = (*env)->NewStringUTF(env, method_name);
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
    if (!env || !symbol || symbol->is_constructor) return 0;
    js_vm_program *nested_program = js_vm_find_preloaded_program_by_identity(symbol->method_identity);
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
    if (!target && symbol->argc == 0 && (char)symbol->ret_tag == 'I') {
        jint int_result = 0;
        js_vm_nested_dispatch_depth++;
        int nested_ok = js_vm_execute_prepared_program_int(env, nested_program, &int_result);
        js_vm_nested_dispatch_depth--;
        if ((*env)->ExceptionCheck(env) || !nested_ok) { (*env)->PopLocalFrame(env, NULL); return -1; }
        (*env)->PopLocalFrame(env, NULL);
        return js_vm_push(stack, stack_cap, sp, js_vm_int_value(int_result)) ? 1 : -1;
    }
    if (!target && symbol->argc == 1 && symbol->arg_tags && symbol->arg_tags[0] == 'I' && (char)symbol->ret_tag == 'I') {
        jint int_arg = args[0].i;
        jint int_result = 0;
        js_vm_nested_dispatch_depth++;
        int nested_ok = js_vm_execute_prepared_program_int_int(env, nested_program, int_arg, &int_result);
        js_vm_nested_dispatch_depth--;
        if ((*env)->ExceptionCheck(env) || !nested_ok) { (*env)->PopLocalFrame(env, NULL); return -1; }
        (*env)->PopLocalFrame(env, NULL);
        return js_vm_push(stack, stack_cap, sp, js_vm_int_value(int_result)) ? 1 : -1;
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


JS_HIDDEN int js_vm_build_state_binding_with_layout_digest(
    jlong entry_token,
    const char *resource_path,
    const unsigned char layout_digest[32],
    unsigned char *out,
    int out_cap
) {
    if (!out || out_cap <= 0 || !layout_digest) return 0;
    char layout_digest_hex[65];
    unsigned char entry_integrity[4];
    int binding_len = 0;
    for (int i = 0; i < 32; i++) snprintf(layout_digest_hex + (i * 2), sizeof(layout_digest_hex) - (size_t)(i * 2), "%02x", layout_digest[i]);
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
    js_vbc4_wipe_volatile(layout_digest_hex, sizeof(layout_digest_hex));
    return binding_len;
}

JS_HIDDEN int js_vm_build_state_binding(
    jlong entry_token,
    const char *resource_path,
    unsigned char *out,
    int out_cap
) {
    unsigned char layout_digest[32];
    int binding_len;
    js_vbc4_copy_scoped_layout_digest(layout_digest);
    binding_len = js_vm_build_state_binding_with_layout_digest(
        entry_token,
        resource_path,
        layout_digest,
        out,
        out_cap);
    js_vbc4_wipe_volatile(layout_digest, sizeof(layout_digest));
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
        if (program && !(*env)->ExceptionCheck(env)) {
            char reason[384];
            snprintf(reason, sizeof(reason), "native VM execution failed for entry=%016llx", (unsigned long long)program->entry_token);
            if (js_vm_last_failure_pc >= 0) {
                snprintf(reason, sizeof(reason), "native VM execution failed for entry=%016llx pc=%d opcode=%d sp=%d raw=%d mask=%d epoch=%d cached=%d insns=%d step=%d limit=%d detail=%s", (unsigned long long)program->entry_token, js_vm_last_failure_pc, js_vm_last_failure_opcode, js_vm_last_failure_sp, js_vm_last_failure_raw_opcode, js_vm_last_failure_mask, js_vm_last_failure_epoch, js_vm_last_failure_cached, js_vm_last_failure_insn_count, js_vm_last_failure_step, js_vm_last_failure_step_limit, js_vm_last_failure_detail);
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

JS_HIDDEN int js_vm_execute_prepared_program_int_void(JNIEnv *env, js_vm_program *program, jint arg0) {
    if (!program) return 0;
    js_vm_value preset_locals[1];
    js_vm_value ret = js_vm_null_value();
    int guest_frame_saved_count = js_vm_guest_frame_count;
    int guest_frame_pushed = js_vm_guest_frame_push(program);
    preset_locals[0] = js_vm_int_value(arg0);
    int ok = js_vm_execute_register_with_preset_locals(env, program, NULL, preset_locals, 1, 'V', &ret);
    js_vm_clear_value(&ret);
    js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed);
    return ok && !(*env)->ExceptionCheck(env);
}

JS_HIDDEN int js_vm_execute_prepared_program_int(JNIEnv *env, js_vm_program *program, jint *out) {
    if (!program || !out) return 0;
    js_vm_value ret = js_vm_null_value();
    int guest_frame_saved_count = js_vm_guest_frame_count;
    int guest_frame_pushed = js_vm_guest_frame_push(program);
    int ok = js_vm_execute_register_with_preset_locals(env, program, NULL, NULL, 0, 'I', &ret);
    if (ok && !(*env)->ExceptionCheck(env)) ok = js_vm_to_int(ret, out);
    js_vm_clear_value(&ret);
    js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed);
    return ok && !(*env)->ExceptionCheck(env);
}

JS_HIDDEN int js_vm_execute_prepared_program_int_int(JNIEnv *env, js_vm_program *program, jint arg0, jint *out) {
    if (!program || !out) return 0;
    js_vm_value preset_locals[1];
    js_vm_value ret = js_vm_null_value();
    int guest_frame_saved_count = js_vm_guest_frame_count;
    int guest_frame_pushed = js_vm_guest_frame_push(program);
    preset_locals[0] = js_vm_int_value(arg0);
    int ok = js_vm_execute_register_with_preset_locals(env, program, NULL, preset_locals, 1, 'I', &ret);
    if (ok && !(*env)->ExceptionCheck(env)) ok = js_vm_to_int(ret, out);
    js_vm_clear_value(&ret);
    js_vm_guest_frame_restore(guest_frame_saved_count, guest_frame_pushed);
    return ok && !(*env)->ExceptionCheck(env);
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

static int js_vm_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char* js_vm_hex_to_utf8_owned(const char *hex) {
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 || hex_len > 0xFFFFu * 2u) return NULL;
    char *out = (char*)malloc(hex_len / 2u + 1u);
    if (!out) return NULL;
    for (size_t i = 0; i < hex_len; i += 2u) {
        int hi = js_vm_hex_nibble(hex[i]);
        int lo = js_vm_hex_nibble(hex[i + 1u]);
        if (hi < 0 || lo < 0) { js_vbc4_wipe_volatile(out, hex_len / 2u); free(out); return NULL; }
        out[i / 2u] = (char)((hi << 4) | lo);
    }
    out[hex_len / 2u] = 0;
    return out;
}

static int js_vm_cp_condy_value(JNIEnv *env, const char *encoded, js_vm_value *out) {
    char *owned = NULL;
    char *parts[6] = {0};
    char *cursor = NULL;
    int ok = 0;
    if (!env || !encoded || !out || strncmp(encoded, "condy|", 6) != 0) return 0;
    owned = js_strdup(encoded);
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
    if (strcmp(parts[0], "condy") != 0 || !parts[2][0]) goto done;
    if (strcmp(parts[1], "str") == 0) {
        if (strcmp(parts[3], "$_c_str") != 0 ||
            strcmp(parts[4], "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;") != 0) goto done;
        char *utf8 = js_vm_hex_to_utf8_owned(parts[5]);
        if (!utf8) goto done;
        jobject s = (*env)->NewStringUTF(env, utf8);
        js_vbc4_wipe_volatile(utf8, strlen(utf8));
        free(utf8);
        if ((*env)->ExceptionCheck(env) || !s) goto done;
        *out = js_vm_object_value(s);
        ok = 1;
    } else if (strcmp(parts[1], "int") == 0) {
        if (strcmp(parts[3], "$_c_int") != 0 ||
            strcmp(parts[4], "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;I)Ljava/lang/Object;") != 0) goto done;
        char *end = NULL;
        long value = strtol(parts[5], &end, 10);
        if (!end || *end != 0 || value < INT32_MIN || value > INT32_MAX) goto done;
        *out = js_vm_int_value((jint)value);
        ok = 1;
    }
done:
    if (owned) { js_vbc4_wipe_volatile(owned, strlen(owned)); free(owned); }
    return ok;
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
                if (js_vm_method_is_instance(p) && js_vm_ldc_type_matches_owner_identity(cp.s, p)) cls = js_vm_receiver_class_from_args(env, args);
                if (!cls) cls = js_vm_find_class_name(env, cp.s);
                *out = js_vm_object_value(cls);
                ok = !(*env)->ExceptionCheck(env) && !js_vm_value_is_null(*out);
            }
            break;
        case JS_VM_LDC_CONDY:
            ok = cp.type == JS_VM_CP_STRING && cp.s && js_vm_cp_condy_value(env, cp.s, out);
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
    char *mapped_method = NULL;
    const char *lookup_name = NULL;
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
    /* VM resources retain the logical helper owner/name while the final JAR
     * may have remapped both the class and its static method.  Resolve the
     * keyed method binding before asking JNI for the method ID, just as the
     * ordinary invoke path does.  If a mapped name is stale, clear only the
     * lookup exception and retain the original-name fallback for compatibility
     * with unrenamed or legacy resources. */
    mapped_method = js_lookup_bound_method(env, parts[3], parts[4], parts[5]);
    lookup_name = mapped_method && mapped_method[0] ? mapped_method : parts[4];
    mid = js_vm_lookup_valid_method_id(env, cls, lookup_name, parts[5], 1);
    if (((*env)->ExceptionCheck(env) || !mid) && mapped_method && mapped_method[0] &&
        strcmp(lookup_name, parts[4]) != 0 && js_vm_valid_method_lookup(parts[4], parts[5])) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        mid = js_vm_lookup_valid_method_id(env, cls, parts[4], parts[5], 1);
    }
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
    free(mapped_method);
    free(tags);
    free(args);
    if (owned) { js_vbc4_wipe_volatile(owned, strlen(owned)); free(owned); }
    return ok;
}

static int js_vm_invoke_dynamic(JNIEnv *env, js_vm_program *p, int cp_idx, js_vm_value *stack, int stack_cap, int *sp) {
    char *indy = js_vm_cp_string_owned(p, cp_idx);
    size_t indy_len = 0u;
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
    jobject captured = NULL;
    if (!indy) return 0;
    indy_len = strlen(indy);

    if (strncmp(indy, "mhstatic|", 9) == 0) {
        ok = js_vm_invoke_dynamic_static_target(env, indy, stack, stack_cap, sp);
        goto js_vm_invoke_dynamic_done;
    }

    if (strncmp(indy, "lambda|", 7) == 0) {
        char *parts[10];
        char *cursor = indy;
        int part_count = 10;
        for (int i = 0; i < part_count; i++) {
            parts[i] = cursor;
            char *bar = strchr(cursor, '|');
            if (i < part_count - 1) {
                if (!bar) { part_count = i + 1; break; }
                *bar = 0;
                cursor = bar + 1;
            } else if (bar) {
                part_count = 0;
            }
        }
        if (part_count == 10) {
            desc = js_strdup(parts[2]);
            if (!desc || !js_vm_descriptor_arg_tags(desc, &tags, &argc)) { ok = 0; goto js_vm_invoke_dynamic_done; }
            if (!js_jni_cache.initialized || !js_jni_cache.object_class) { ok = 0; goto js_vm_invoke_dynamic_done; }
            captured = (*env)->NewObjectArray(env, argc, js_jni_cache.object_class, NULL);
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
                uint32_t impl_tag_value = 0u;
                if (!js_parse_u32_token(parts[3], &impl_tag_value) || impl_tag_value > INT32_MAX) {
                    ok = 0;
                    goto js_vm_invoke_dynamic_done;
                }
                char *helper_owner = js_first_loader_owner_from_property(env);
                if (!helper_owner || !helper_owner[0]) { free(helper_owner); helper_owner = js_helper_owner("Jni", "Micro", "kernel", "Helper"); }
                jclass helper_cls = helper_owner ? js_vm_find_class_name(env, helper_owner) : NULL;
                jmethodID create_mid = helper_cls ? (*env)->GetStaticMethodID(env, helper_cls, "createSamLambda", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;") : NULL;
                jstring sam_name = (*env)->NewStringUTF(env, parts[1]);
                jstring factory_desc = (*env)->NewStringUTF(env, parts[2]);
                jstring owner = (*env)->NewStringUTF(env, parts[4]);
                jstring name = (*env)->NewStringUTF(env, parts[5]);
                jstring impl_desc = (*env)->NewStringUTF(env, parts[6]);
                jstring sam_desc = (*env)->NewStringUTF(env, parts[7]);
                jstring instantiated_desc = (*env)->NewStringUTF(env, parts[8]);
                jstring encoded_options = (*env)->NewStringUTF(env, parts[9]);
                jint impl_tag = (jint)impl_tag_value;
                result = (helper_cls && create_mid && sam_name && factory_desc && owner && name && impl_desc && sam_desc && instantiated_desc && encoded_options) ? (*env)->CallStaticObjectMethod(env, helper_cls, create_mid, sam_name, factory_desc, owner, name, impl_desc, impl_tag, sam_desc, instantiated_desc, encoded_options, captured) : NULL;
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
    if (captured) (*env)->DeleteLocalRef(env, captured);
    free(desc);
    free(tags);
    if (values) js_vm_clear_value_range(values, argc);
    free(values);
    if (indy) { js_vbc4_wipe_volatile(indy, indy_len); free(indy); }
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

JS_PROTECTED static uint32_t js_vm_dispatch_profile_for(const js_vm_program *program) {
    if (!program) return 0u;
    uint32_t x = (uint32_t)program->entry_token ^ (uint32_t)((uint64_t)program->entry_token >> 32);
    x ^= program->method_local_profile + 0x9E3779B9u;
    x ^= program->vbc4_flags * 0x45D9F3Bu;
    for (int i = 0; i < 16; i++) x = (x << 5) ^ (x >> 27) ^ (uint32_t)program->nonce[i];
    x ^= x >> 16; x *= 0x7FEB352Du; x ^= x >> 15; x *= 0x846CA68Bu; x ^= x >> 16;
    return x % 6u;
}

JS_PROTECTED static uint32_t js_vm_dispatch_profile_tag_for(const js_vm_program *program) {
    if (!program) return 0u;
    uint64_t token = (uint64_t)program->entry_token;
    uint32_t x = (uint32_t)(token ^ (token >> 32));
    x ^= program->method_local_profile ^ ((program->is_static ? 1u : 0u) * 0x45D9F3Bu) ^ (program->native_vm_profile_id * 0x27D4EB2Du);
    const unsigned char *path = (const unsigned char*)(program->resource_path ? program->resource_path : "");
    for (const unsigned char *p = path; p && *p; ++p) {
        x ^= (uint32_t)(*p);
        x *= 0x01000193u;
        x ^= x >> 13;
    }
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    return x ^ (x >> 16);
}

JS_PROTECTED static int js_vm_dispatch_profile_tag_matches(const js_vm_program *program) {
    if (!program || program->dispatch_profile_tag == 0u) return 0;
    if (program->native_vm_profile_id != JS_NATIVE_VM_PROFILE_ID) return 0;
    return js_vm_dispatch_profile_tag_for(program) == program->dispatch_profile_tag;
}

JS_PROTECTED static int js_vm_preload_entry_auth_matches(
    const char *token_hex,
    const char *resource_path,
    const char *manifest_path,
    const char *shard_text,
    const char *mesh,
    const char *profile,
    const char *expected
) {
    if (!token_hex || !resource_path || !manifest_path || !shard_text || !mesh || !profile || !expected) return 0;
    if (strlen(mesh) != 64u || strlen(expected) != 16u) return 0;
    js_sha256_ctx ctx;
    unsigned char digest[32];
    char actual[17];
    static const char hex[] = "0123456789abcdef";
    js_sha256_init(&ctx);
    static const unsigned char auth_domain[] = "jsc1-method-auth-v1";
    js_sha256_update(&ctx, auth_domain, (int)(sizeof(auth_domain) - 1));
    unsigned char zero = 0;
    js_sha256_update(&ctx, &zero, 1); js_sha256_update(&ctx, (const unsigned char*)token_hex, (int)strlen(token_hex));
    js_sha256_update(&ctx, &zero, 1); js_sha256_update(&ctx, (const unsigned char*)resource_path, (int)strlen(resource_path));
    js_sha256_update(&ctx, &zero, 1); js_sha256_update(&ctx, (const unsigned char*)manifest_path, (int)strlen(manifest_path));
    js_sha256_update(&ctx, &zero, 1); js_sha256_update(&ctx, (const unsigned char*)shard_text, (int)strlen(shard_text));
    js_sha256_update(&ctx, &zero, 1); js_sha256_update(&ctx, (const unsigned char*)mesh, (int)strlen(mesh));
    js_sha256_update(&ctx, &zero, 1); js_sha256_update(&ctx, (const unsigned char*)profile, (int)strlen(profile));
    js_sha256_final(&ctx, digest);
    for (int i = 0; i < 8; i++) {
        actual[i * 2] = hex[(digest[i] >> 4) & 0x0F];
        actual[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    actual[16] = 0;
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= (int)((unsigned char)actual[i] ^ (unsigned char)expected[i]);
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    js_vbc4_wipe_volatile(actual, sizeof(actual));
    return diff == 0;
}

JS_PROTECTED static int js_vm_profile_next_pc(uint32_t profile, int current_pc, int sequential_pc, int target_pc, int has_target, uint32_t drift, int step, int sp) {
    if (has_target) {
        uint32_t guard = ((uint32_t)target_pc ^ drift ^ (uint32_t)(step * 0x45D9F3Bu) ^ (uint32_t)(sp * 0x119DE1F3u));
        if (profile == 4u && ((guard ^ (guard >> 7)) & 1u)) return target_pc;
        if (profile == 5u) return (int)((uint32_t)target_pc ^ ((guard & 0u) << 1));
        return target_pc;
    }
    if (profile == 1u) return current_pc + 1;
    if (profile == 2u) return sequential_pc + (int)((drift >> (step & 7)) & 0u);
    if (profile == 3u) {
        int next = current_pc;
        next += 1;
        return next;
    }
    return sequential_pc;
}

static uint32_t js_vm_dispatch_progress_salt(const js_vm_program *program, int pc, uint32_t drift_state) {
    uint32_t salt = js_vm_dispatch_salt(program, pc);
    salt ^= drift_state + 0xA5A5A5A5u + (salt << 6) + (salt >> 2);
    return js_vm_method_local_salt(program, salt);
}

JS_PROTECTED static uint32_t js_vm_profile_case_salt(uint32_t profile, const js_vm_program *program, int pc, uint32_t drift_state, int dispatch_step, int sp) {
    uint32_t salt = js_vm_dispatch_progress_salt(program, pc, drift_state);
    uint32_t mix = salt ^ (profile * 0x9E3779B9u) ^ (uint32_t)(dispatch_step * 0x85EBCA6Bu) ^ (uint32_t)(sp * 0xC2B2AE35u);
    mix ^= mix >> 16;
    mix *= 0x7FEB352Du;
    mix ^= mix >> 15;
    if (profile == 1u) return salt ^ ((mix & 0u) << 1);
    if (profile == 2u) return (salt + (mix & 0u)) ^ ((mix >> 11) & 0u);
    if (profile == 3u) { volatile uint32_t shaped = salt ^ (mix & 0u); return shaped; }
    if (profile == 4u) return salt ^ js_vbc4_rotl32(mix & 0u, (int)(mix & 15u));
    if (profile == 5u) return (mix & 1u) ? salt : (salt ^ (mix & 0u));
    return salt;
}

JS_PROTECTED static int js_vm_profile_case_matches(uint32_t profile, int opcode, int expected, uint32_t salt) {
    if (profile == 0u) {
        return js_vm_case_match(opcode, expected, salt);
    }
    if (profile == 1u) {
        int folded = opcode ^ (int)(salt & 0u);
        int target = expected ^ (int)(salt & 0u);
        return js_vm_case_match(folded, target, salt);
    }
    if (profile == 2u) {
        switch ((opcode ^ expected ^ (int)(salt & 0u)) & 0x3) {
            case 0: return js_vm_case_match(opcode, expected, salt);
            case 1: return js_vm_case_match(opcode ^ (int)(salt & 0u), expected, salt);
            case 2: return js_vm_case_match(opcode, expected ^ (int)(salt & 0u), salt);
            default: return js_vm_case_match(opcode, expected, salt ^ (salt & 0u));
        }
    }
    if (profile == 3u) {
        volatile int lhs = opcode;
        volatile int rhs = expected;
        if (lhs == rhs) return js_vm_case_match(opcode, expected, salt);
        return js_vm_case_match(opcode, expected, salt);
    }
    if (profile == 4u) {
        int delta = opcode - expected;
        if (delta == 0) return js_vm_case_match(opcode, expected, salt);
        return js_vm_case_match(expected + delta, expected, salt);
    }
    if (profile == 5u) {
        int selectors[2];
        selectors[0] = opcode;
        selectors[1] = opcode ^ (int)(salt & 0u);
        return js_vm_case_match(selectors[(salt >> 31) & 1u], expected, salt);
    }
    return js_vm_case_match(opcode, expected, salt);
}

JS_PROTECTED static int js_vm_profile_transition_due(uint32_t profile, const js_vm_program *program, uint32_t drift_state, int dispatch_step, int fault_pc, int sp) {
    if (profile == 1u) {
        return js_vm_dispatch_rotation_due(program, drift_state ^ ((uint32_t)fault_pc & 0u), dispatch_step, fault_pc, sp);
    }
    if (profile == 2u) {
        uint32_t mixed = drift_state ^ (uint32_t)(dispatch_step * 0x9E3779B9u) ^ (uint32_t)(sp * 0x45D9F3Bu);
        return js_vm_dispatch_rotation_due(program, drift_state ^ (mixed & 0u), dispatch_step, fault_pc, sp);
    }
    if (profile == 3u) {
        volatile int due = js_vm_dispatch_rotation_due(program, drift_state, dispatch_step, fault_pc, sp);
        return due;
    }
    if (profile == 4u) {
        return js_vm_dispatch_rotation_due(program, drift_state, dispatch_step + (int)((drift_state >> 5) & 0u), fault_pc, sp);
    }
    if (profile == 5u) {
        uint32_t opaque = js_vm_dispatch_progress_salt(program, fault_pc, drift_state);
        if ((opaque & 1u) || !(opaque & 1u)) return js_vm_dispatch_rotation_due(program, drift_state, dispatch_step, fault_pc, sp);
    }
    return js_vm_dispatch_rotation_due(program, drift_state, dispatch_step, fault_pc, sp);
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
    if (opcode == JS_VM_INVOKESTATIC && p) {
        char *raw_ref = js_vm_cp_string_owned(p, cp_idx);
        js_vm_method_ref raw_mr;
        memset(&raw_mr, 0, sizeof(raw_mr));
        if (raw_ref && js_vm_parse_method_ref(raw_ref, &raw_mr)) {
            unsigned char identity[32];
            cp_self_call = js_vm_method_identity_for_ref(&raw_mr, identity) && memcmp(identity, p->method_identity, sizeof(identity)) == 0;
            js_vbc4_wipe_volatile(identity, sizeof(identity));
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
                else { js_vm_debug_alloc_probe("constructor-target", env, alloc_cls, target_value.uninit_type); target = (*env)->AllocObject(env, alloc_cls); }
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
                                mid = js_vm_lookup_valid_method_id(env, target_cls, dyn_lookup, dyn_mr.desc, 0);
                                if (((*env)->ExceptionCheck(env) || !mid) && dyn_mapped && dyn_mapped[0] && strcmp(dyn_lookup, dyn_mr.name) != 0 && js_vm_valid_method_lookup(dyn_mr.name, dyn_mr.desc)) {
                                    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                                    mid = js_vm_lookup_valid_method_id(env, target_cls, dyn_mr.name, dyn_mr.desc, 0);
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

/* A folded super-operator fuses `const, <binop>` where <binop> ranges over the
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

static int js_vm_decode_cfg_targets(js_vm_program *program) {
    if (!program || !program->insns || program->insn_count <= 0) return 0;
    if (program->exception_count > 0 && !program->exceptions) return 0;
    int seed = js_vm_load_resident_build_seed(program);
    for (int index = 0; index < program->insn_count; index++) {
        jint opcode = js_vm_load_resident_opcode(program, index);
        for (int operand_index = 0; operand_index < program->insns[index].op_count; operand_index++) {
            if (!js_vm_opcode_target_operand(opcode, operand_index)) continue;
            jint encoded = js_vm_load_resident_operand(program, index, operand_index);
            int decoded = js_vbc4_cfg_decode_index(seed, program->insn_count, encoded);
            if (decoded < 0 || decoded >= program->insn_count) return 0;
            program->insns[index].ops[operand_index] = js_vm_store_resident_operand(program, index, operand_index, decoded);
        }
    }
    if (!program->cfg_exceptions_decoded) {
        for (int index = 0; index < program->exception_count; index++) {
            js_vm_exception entry = js_vm_load_resident_exception(program, index);
            int start = js_vbc4_cfg_decode_index(seed, program->insn_count, entry.start);
            int end = js_vbc4_cfg_decode_index(seed, program->insn_count, entry.end);
            int handler = js_vbc4_cfg_decode_index(seed, program->insn_count, entry.handler);
            if (start < 0 || end < 0 || handler < 0 || start >= end || end > program->insn_count || handler >= program->insn_count) return 0;
            program->exceptions[index].start = js_vm_store_resident_exception_field(program, index, 0, start);
            program->exceptions[index].end = js_vm_store_resident_exception_field(program, index, 1, end);
            program->exceptions[index].handler = js_vm_store_resident_exception_field(program, index, 2, handler);
        }
        program->cfg_exceptions_decoded = 1;
    }
    return 1;
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
    if (source->cfg_exceptions_decoded) return 0;
    if (source->exception_count > 0 && !source->exceptions) return 0;
    if (!js_vm_validate_register_program(source)) return 0;
    js_vm_copy_execution_program_header(execution, source);
    /* CFG target decoding mutates exception offsets. Keep the encoded source
     * immutable so failed preload/retry paths never apply the inverse twice. */
    execution->exceptions = NULL;
    execution->borrowed_exceptions = 0;
    execution->cfg_exceptions_decoded = 0;
    if (source->exception_count > 0) {
        execution->exceptions = (js_vm_exception*)calloc((size_t)source->exception_count, sizeof(js_vm_exception));
        if (!execution->exceptions) return 0;
        memcpy(execution->exceptions, source->exceptions, (size_t)source->exception_count * sizeof(js_vm_exception));
    }
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
    return execution->insn_count > 0 && execution->insns != NULL && js_vm_decode_cfg_targets(execution);
}

static int js_vm_execute_with_preset_locals(JNIEnv *env, js_vm_program *p, jobjectArray args, const js_vm_value *preset_locals, int preset_count, char ret_desc, js_vm_value *ret) {
    if (!js_vm_dispatch_profile_tag_matches(p)) {
        if (ret) *ret = js_vm_null_value();
        js_vm_last_failure_detail[0] = 0;
        snprintf(js_vm_last_failure_detail, sizeof(js_vm_last_failure_detail), "dispatch profile tag mismatch");
        return 0;
    }
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
    if (preset_locals && preset_count > 0) {
        int count = preset_count < local_cap ? preset_count : local_cap;
        for (int i = 0; i < count; i++) {
            locals[js_vm_local_perm(i, local_cap, local_perm_mul, local_perm_add)] = preset_locals[i];
        }
    } else if (args) {
        jsize argc = (*env)->GetArrayLength(env, args);
        /* The dispatch stub boxes one Object[] element per logical argument (plus a
         * leading `this` for instance methods), but the VBC4 body addresses locals by
         * JVM slot, where long/double parameters occupy two slots. Map each boxed
         * element to its JVM slot using the original descriptor so that arguments after
         * a long/double land in the correct local; a dense i->locals[i] mapping shifts
         * every later argument and surfaces as a null receiver / wrong value at runtime. */
        const char *arg_tags = p->argument_tags;
        int desc_argc = p->argument_count;
        int is_static = p->is_static != 0;
        int have_desc = arg_tags != NULL && desc_argc >= 0;
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
    }
    *ret = js_vm_null_value();
    int dispatch_step = 0;
    uint32_t vm_trace_state = 0;  /* accumulates anti-trace detection state */
    uint32_t vm_dispatch_drift_state = js_vm_dispatch_drift_step(p, js_vm_shared_dispatch_seed_for(p), 0, pc, sp);
    uint32_t js_vm_dispatch_profile = js_vm_dispatch_profile_for(p);
    uint64_t requested_step_limit = (uint64_t)(p->insn_count > 0 ? p->insn_count : 1) * UINT64_C(250000);
    if (requested_step_limit < UINT64_C(1000000)) requested_step_limit = UINT64_C(1000000);
    if (requested_step_limit > (uint64_t)INT32_MAX) requested_step_limit = (uint64_t)INT32_MAX;
    int execution_step_limit = (int)requested_step_limit;
    uint32_t saved_trace_poison_seed = js_vm_trace_poison_seed;
    js_vm_trace_poison_seed = 0;  /* reset CP poison for this execution frame only */
    while (ok && !returned && pc >= 0 && pc < p->insn_count) {
        if (dispatch_step >= execution_step_limit) {
            js_vm_last_failure_pc = pc;
            /* Clear sensitive window before fail-closed exit */
            if (locals_heap && locals) js_vbc4_wipe_volatile(locals, sizeof(js_vm_value) * (size_t)local_cap);
            if (stack_heap && stack) js_vbc4_wipe_volatile(stack, sizeof(js_vm_value) * (size_t)stack_cap);
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
        /* Native integrity checkpoint: verify hot path integrity before each dispatch group.
         * Frequency: every 128 steps (amortized). Fail-closed on corruption. */
        if ((dispatch_step & 127) == 0 && js_vm_hot_integrity_baseline_clean) {
            if (!js_vm_hot_integrity_clean()) {
                /* Hot path patched mid-execution: poison cache and fail-closed */
                if (p->insns && p->insn_count > 0) {
                    for (int poison_idx = 0; poison_idx < p->insn_count && poison_idx < 8; poison_idx++) {
                        p->insns[poison_idx].opcode ^= 0xDEADu;
                        p->insns[poison_idx].opcode_epoch ^= 0xBEEFu;
                    }
                }
                js_vm_last_failure_pc = pc;
                js_vm_last_failure_opcode = JS_VM_UNSUPPORTED;
                js_vm_last_failure_sp = sp;
                ok = 0;
                break;
            }
        }
        js_vm_dispatch_fetch:
        /* Anti-trace trap: detect debugger/trace attachment */
        if (js_vm_anti_trace_check(dispatch_step, &vm_trace_state)) {
            /* Poison the dispatch: corrupt the next opcode to land on a wrong handler.
             * This makes single-step traces produce garbage instruction sequences. */
            p->insns[pc >= 0 && pc < p->insn_count ? pc : 0].opcode ^= (jint)(vm_trace_state & 0xFFu);
            /* Poison resident epoch rotation and cache state */
            p->resident_rotation_epoch ^= (uint32_t)(vm_trace_state * 0x45D9F3Bu);
            /* Poison a few upcoming opcodes to corrupt trace prediction */
            for (int poison_ahead = 1; poison_ahead <= 3 && pc + poison_ahead < p->insn_count; poison_ahead++) {
                uint32_t poison_mix = vm_trace_state ^ (uint32_t)(dispatch_step + poison_ahead);
                p->insns[pc + poison_ahead].opcode ^= (jint)((poison_mix >> (poison_ahead * 3)) & 0x7Fu);
            }
        }
        /* Bogus handler row injection: 1/16 chance to execute semantically-noop bogus path */
        int execute_bogus = ((vm_dispatch_drift_state ^ (uint32_t)dispatch_step) & 0xFu) == 0x7u;
        int fault_pc = pc;
        jobject pending_throw = NULL;
        js_vm_insn active_insn = p->insns[pc];
        jint active_raw_opcode = p->insns[pc].opcode;
        jint active_mask = js_vm_resident_opcode_mask(p, pc);
        jint active_epoch = p->insns[pc].opcode_epoch;
        active_insn.opcode = js_vm_canonical_opcode(active_raw_opcode ^ active_mask);
        pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc + 1, 0, 0, vm_dispatch_drift_state, dispatch_step, sp);
        /* Rotating the resident epoch rewraps the complete instruction array.
         * Keep per-opcode rewrap on every dispatch, but run the whole-program
         * rotation at a build-local coarse cadence (128/256/512 steps). */
        uint32_t resident_rotation_mask = ((uint32_t)JS_VBC4_DISPATCH_STEP_MASK << 4) | 0x0Fu;
        if ((((uint32_t)dispatch_step & resident_rotation_mask) == 0u) &&
            js_vm_profile_transition_due(js_vm_dispatch_profile, p, vm_dispatch_drift_state, dispatch_step, fault_pc, sp)) {
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
                int resident_index = fault_pc;
                for (int operand_index = 0; operand_index < active_insn.op_count; operand_index++) {
                    decoded_ops[operand_index] = js_vm_profile_fetch_operand(p, js_vm_dispatch_profile, resident_index, operand_index, vm_dispatch_drift_state, dispatch_step, sp);
                }
                active_insn.ops = decoded_ops;
            }
        } else {
            active_insn.ops = NULL;
        }
        /* Bogus handler: noop computation that pollutes trace/symbolic analysis */
        if (execute_bogus) {
            volatile jint bogus_acc = (jint)(vm_dispatch_drift_state ^ (uint32_t)pc ^ (uint32_t)sp);
            bogus_acc = (bogus_acc << 3) ^ (bogus_acc >> 5);
            bogus_acc = bogus_acc * 0x01000193 + dispatch_step;
            (void)bogus_acc; /* prevent optimization */
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
#define JS_VM_DISPATCH(insn_ptr) int js_vm_dispatch_opcode = (insn_ptr)->opcode; uint32_t js_vm_dispatch_salt_value = js_vm_poison_dispatch_salt(js_vm_profile_case_salt(js_vm_dispatch_profile, p, pc, vm_dispatch_drift_state, dispatch_step, sp), vm_trace_state); int js_vm_dispatch_matched = 0; if (0)
#define JS_VM_CASE(x) (void)0; } if (!js_vm_dispatch_matched && js_vm_profile_case_matches(js_vm_dispatch_profile, js_vm_dispatch_opcode, (x), js_vm_dispatch_salt_value)) js_vm_dispatch_matched = 1; if (js_vm_dispatch_matched) {
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
            JS_VM_CASE(JS_VM_LDC_CONDY)
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
                if (ok) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ia, 1, vm_dispatch_drift_state, dispatch_step, sp);
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
                if (ok && ((insn->opcode == JS_VM_IFEQ && ia == 0) || (insn->opcode == JS_VM_IFNE && ia != 0) || (insn->opcode == JS_VM_IFLT && ia < 0) || (insn->opcode == JS_VM_IFGE && ia >= 0) || (insn->opcode == JS_VM_IFGT && ia > 0) || (insn->opcode == JS_VM_IFLE && ia <= 0))) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ops[0], 1, vm_dispatch_drift_state, dispatch_step, sp);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IF_ICMPEQ) JS_VM_CASE(JS_VM_IF_ICMPNE) JS_VM_CASE(JS_VM_IF_ICMPLT) JS_VM_CASE(JS_VM_IF_ICMPGE) JS_VM_CASE(JS_VM_IF_ICMPGT) JS_VM_CASE(JS_VM_IF_ICMPLE)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia) && js_vm_to_int(b, &ib);
                if (ok && ((insn->opcode == JS_VM_IF_ICMPEQ && ia == ib) || (insn->opcode == JS_VM_IF_ICMPNE && ia != ib) || (insn->opcode == JS_VM_IF_ICMPLT && ia < ib) || (insn->opcode == JS_VM_IF_ICMPGE && ia >= ib) || (insn->opcode == JS_VM_IF_ICMPGT && ia > ib) || (insn->opcode == JS_VM_IF_ICMPLE && ia <= ib))) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ops[0], 1, vm_dispatch_drift_state, dispatch_step, sp);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IF_ACMPEQ) JS_VM_CASE(JS_VM_IF_ACMPNE)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &b) && js_vm_pop(stack, &sp, &a);
                if (ok && a.type != JS_VM_VAL_OBJECT && a.type != JS_VM_VAL_NULL) ok = 0;
                if (ok && b.type != JS_VM_VAL_OBJECT && b.type != JS_VM_VAL_NULL) ok = 0;
                if (ok) { int eq = js_vm_value_is_null(a) && js_vm_value_is_null(b); if (!eq && !js_vm_value_is_null(a) && !js_vm_value_is_null(b)) eq = (*env)->IsSameObject(env, a.o, b.o); if ((insn->opcode == JS_VM_IF_ACMPEQ && eq) || (insn->opcode == JS_VM_IF_ACMPNE && !eq)) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ops[0], 1, vm_dispatch_drift_state, dispatch_step, sp); }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_GOTO)
                ok = insn->op_count >= 1;
                if (ok) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ops[0], 1, vm_dispatch_drift_state, dispatch_step, sp);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_JSR)
                ok = insn->op_count >= 1 && js_vm_push(stack, stack_cap, &sp, js_vm_int_value(pc));
                if (ok) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ops[0], 1, vm_dispatch_drift_state, dispatch_step, sp);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_IFNULL) JS_VM_CASE(JS_VM_IFNONNULL)
                ok = insn->op_count >= 1 && js_vm_pop(stack, &sp, &a);
                if (ok) { int is_null = js_vm_value_is_null(a); if ((insn->opcode == JS_VM_IFNULL && is_null) || (insn->opcode == JS_VM_IFNONNULL && !is_null)) pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, ops[0], 1, vm_dispatch_drift_state, dispatch_step, sp); }
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
                ok = js_vm_pop(stack, &sp, &a);
                if (ok) ok = js_vm_monitor_enter(env, a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_MONITOREXIT)
                ok = js_vm_pop(stack, &sp, &a);
                if (ok) ok = js_vm_monitor_exit(env, a);
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_TABLESWITCH)
                ok = insn->op_count >= 3 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok) { int min = ops[0], max = ops[1]; pc = (ia < min || ia > max) ? ops[2] : ops[3 + (ia - min)]; }
                JS_VM_BREAK;
            JS_VM_CASE(JS_VM_LOOKUPSWITCH)
                ok = insn->op_count >= 2 && js_vm_pop(stack, &sp, &a) && js_vm_to_int(a, &ia);
                if (ok) { int npairs = ops[0]; int target = ops[1]; if (insn->op_count < 2 + npairs * 2) { ok = 0; JS_VM_BREAK; } for (int i = 0; i < npairs; i++) if (ops[2 + i * 2] == ia) { target = ops[3 + i * 2]; break; } pc = js_vm_profile_next_pc(js_vm_dispatch_profile, fault_pc, pc, target, 1, vm_dispatch_drift_state, dispatch_step, sp); }
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
    /* Publish this execution state for later virtualized methods. */
    js_vm_shared_dispatch_evolve(p, vm_dispatch_drift_state, dispatch_step);
    js_vm_trace_poison_seed = saved_trace_poison_seed;
    return ok;
}

JS_HIDDEN int js_vm_execute(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret) {
    return js_vm_execute_with_preset_locals(env, p, args, NULL, 0, ret_desc, ret);
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
    js_vm_execute_resource_int_void_by_token(env, cls, entryToken, arg0);
    (*env)->PopLocalFrame(env, NULL);
}

JS_LOCAL jint JNICALL
jsn_r25(JNIEnv *env, jclass cls, jlong entryToken)
{
    if ((*env)->PushLocalFrame(env, 256) != 0) {
        js_vm_fail_closed(env, "native VM local frame allocation failed");
        return 0;
    }
    jint result = js_vm_execute_resource_int_by_token(env, cls, entryToken);
    (*env)->PopLocalFrame(env, NULL);
    return result;
}

JS_LOCAL jint JNICALL
jsn_r26(JNIEnv *env, jclass cls, jlong entryToken, jint arg0)
{
    if ((*env)->PushLocalFrame(env, 256) != 0) {
        js_vm_fail_closed(env, "native VM local frame allocation failed");
        return 0;
    }
    jint result = js_vm_execute_resource_int_int_by_token(env, cls, entryToken, arg0);
    (*env)->PopLocalFrame(env, NULL);
    return result;
}


static const unsigned char JS_JSE_CLASS_DERIVE_LABEL[] = "javashroud-vbc4-jse-class-v1";

/* HKDF-SHA256 (RFC 5869) class-encryption key derivation. Runs ONLY inside the
 * sealed native kernel: ikm is the resident per-build anchor key, the label is
 * the extract salt, info is keyId||salt. Byte-for-byte identical to the Kotlin
 * build-time derivation so a build-time key recomputes at runtime. */
static int js_hkdf_sha256_class_key(const unsigned char *info, int info_len, unsigned char *out, int out_len) {
    if (out_len < 1 || out_len > 255 * 32) return 0;
    unsigned char prk[32];
    const unsigned char *xparts[1];
    int xlens[1];
    unsigned char root[32];
    if (!js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT]) return 0;
    js_rrk_xor_assemble(&js_runtime_resource_key_shares[JS_RRK_ANCHOR_SLOT][0][0], JS_RRK_SHARE_COUNT, root);
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
    if (!js_vm_sensitive_path_guard(env, (const void*)jsn_k10, 1)) return NULL;
    if (!js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT]) return NULL;
    if (length < 1 || length > 64) return NULL;
    if (!keyIdArr || !saltArr) return NULL;
    jsize id_len = (*env)->GetArrayLength(env, keyIdArr);
    jsize salt_len = (*env)->GetArrayLength(env, saltArr);
    if (id_len < 0 || salt_len < 0 || id_len > 4096 || salt_len > 4096 || id_len > 4096 - salt_len) return NULL;
    size_t info_len = (size_t)id_len + (size_t)salt_len;
    unsigned char *info = (unsigned char*)malloc(info_len != 0u ? info_len : 1u);
    if (!info) return NULL;
    if (id_len > 0) (*env)->GetByteArrayRegion(env, keyIdArr, 0, id_len, (jbyte*)info);
    if (salt_len > 0) (*env)->GetByteArrayRegion(env, saltArr, 0, salt_len, (jbyte*)(info + id_len));
    if ((*env)->ExceptionCheck(env)) {
        js_vbc4_wipe_volatile(info, info_len);
        free(info);
        return NULL;
    }
    unsigned char derived[64];
    int ok = js_hkdf_sha256_class_key(info, (int)info_len, derived, (int)length);
    js_vbc4_wipe_volatile(info, info_len);
    free(info);
    if (!ok) { js_vbc4_wipe_volatile(derived, sizeof(derived)); return NULL; }
    jbyteArray out = (*env)->NewByteArray(env, length);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, length, (jbyte*)derived);
    js_vbc4_wipe_volatile(derived, sizeof(derived));
    return out;
}

JS_LOCAL jbyteArray JNICALL
jsn_k14(JNIEnv *env, jclass cls, jbyteArray key_id_array, jbyteArray salt_array,
        jbyteArray nonce_array, jbyteArray ciphertext_array, jbyteArray aad_array,
        jint key_length)
{
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsn_k14, 1)) return NULL;
    if (!env || !key_id_array || !salt_array || !nonce_array || !ciphertext_array || !aad_array) return NULL;
    if (key_length != 16 && key_length != 32) return NULL;
    if (!js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT]) return NULL;

    jsize key_id_len = (*env)->GetArrayLength(env, key_id_array);
    jsize salt_len = (*env)->GetArrayLength(env, salt_array);
    jsize nonce_len = (*env)->GetArrayLength(env, nonce_array);
    jsize ciphertext_len = (*env)->GetArrayLength(env, ciphertext_array);
    jsize aad_len = (*env)->GetArrayLength(env, aad_array);
    if (key_id_len < 0 || salt_len < 0 || nonce_len != 12 || ciphertext_len < 16 ||
        aad_len < 0 || ciphertext_len > 64 * 1024 * 1024 || aad_len > 1024 * 1024) return NULL;
    if (key_id_len > 4096 || salt_len > 4096 || key_id_len > 4096 - salt_len) return NULL;

    size_t info_len = (size_t)key_id_len + (size_t)salt_len;
    unsigned char *info = (unsigned char*)malloc(info_len != 0u ? info_len : 1u);
    unsigned char nonce[12] = {0};
    unsigned char *ciphertext = (unsigned char*)malloc((size_t)ciphertext_len);
    unsigned char *aad = (unsigned char*)malloc((size_t)aad_len != 0u ? (size_t)aad_len : 1u);
    unsigned char derived[32] = {0};
    size_t plain_len = (size_t)ciphertext_len - 16u;
    unsigned char *plain = plain_len != 0u ? (unsigned char*)malloc(plain_len) : NULL;
    jbyteArray result = NULL;
    int ok = 0;

    if (!info || !ciphertext || !aad || (plain_len != 0u && !plain)) goto cleanup;
    if (key_id_len > 0) (*env)->GetByteArrayRegion(env, key_id_array, 0, key_id_len, (jbyte*)info);
    if (salt_len > 0) (*env)->GetByteArrayRegion(env, salt_array, 0, salt_len, (jbyte*)(info + key_id_len));
    (*env)->GetByteArrayRegion(env, nonce_array, 0, nonce_len, (jbyte*)nonce);
    (*env)->GetByteArrayRegion(env, ciphertext_array, 0, ciphertext_len, (jbyte*)ciphertext);
    if (aad_len > 0) (*env)->GetByteArrayRegion(env, aad_array, 0, aad_len, (jbyte*)aad);
    if ((*env)->ExceptionCheck(env)) goto cleanup;

    if (!js_hkdf_sha256_class_key(info, (int)info_len, derived, key_length)) goto cleanup;
    if (!js_aes_gcm_decrypt(derived, (size_t)key_length, nonce, aad, (size_t)aad_len,
                            ciphertext, (size_t)ciphertext_len, plain)) {
        js_vm_throw_new(env, "java/lang/SecurityException", "encrypted class authentication failed");
        goto cleanup;
    }
    result = (*env)->NewByteArray(env, (jsize)plain_len);
    if (!result) goto cleanup;
    if (plain_len > 0u) (*env)->SetByteArrayRegion(env, result, 0, (jsize)plain_len, (const jbyte*)plain);
    if ((*env)->ExceptionCheck(env)) {
        result = NULL;
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (info) { js_vbc4_wipe_volatile(info, info_len); free(info); }
    js_vbc4_wipe_volatile(nonce, sizeof(nonce));
    if (ciphertext) { js_vbc4_wipe_volatile(ciphertext, (size_t)ciphertext_len); free(ciphertext); }
    if (aad) { js_vbc4_wipe_volatile(aad, (size_t)aad_len); free(aad); }
    js_vbc4_wipe_volatile(derived, sizeof(derived));
    if (plain) { js_vbc4_wipe_volatile(plain, plain_len); free(plain); }
    return ok ? result : NULL;
}

/* Fill a share with per-process entropy so a memory dump of any single share
 * reveals nothing about the root key. Mix timing, address, and counter inputs
 * through HMAC-SHA256 rather than exposing a reversible PRNG state. */
static volatile uint64_t js_rrk_entropy_roll = 0;
static void js_rrk_fill_entropy(unsigned char out[32]) {
    unsigned char seed[32] = {0};
    uint64_t ticks = js_vm_probe_monotonic_ticks();
    uint64_t cycles = js_vm_probe_rdtsc();
    uintptr_t stack_address = (uintptr_t)&out;
    uint64_t roll = (js_rrk_entropy_roll += 0xA24BAED4963EE407ULL);
    memcpy(seed, &ticks, sizeof(ticks));
    memcpy(seed + 8, &cycles, sizeof(cycles));
    memcpy(seed + 16, &stack_address, sizeof(stack_address));
    memcpy(seed + 24, &roll, sizeof(roll));
    static const unsigned char domain[] = "javashroud-runtime-share-entropy-v1";
    const unsigned char *parts[2] = { domain, seed };
    const int lens[2] = { (int)(sizeof(domain) - 1), (int)sizeof(seed) };
    unsigned char digest[32];
    js_hmac_sha256_with_key(seed, (int)sizeof(seed), parts, lens, 2, digest);
    for (int i = 0; i < 32; i++) {
        out[i] = digest[i];
    }
    js_vbc4_wipe_volatile(seed, sizeof(seed));
    js_vbc4_wipe_volatile(digest, sizeof(digest));
}

static void js_rrk_split_runtime_value(const unsigned char raw[32], unsigned char shares[JS_RRK_SHARE_COUNT][32])
{
    for (int s = 0; s < JS_RRK_SHARE_COUNT - 1; s++) js_rrk_fill_entropy(shares[s]);
    for (int b = 0; b < 32; b++) {
        unsigned char acc = raw[b];
        for (int s = 0; s < JS_RRK_SHARE_COUNT - 1; s++) acc = (unsigned char)(acc ^ shares[s][b]);
        shares[JS_RRK_SHARE_COUNT - 1][b] = acc;
    }
}

static void js_runtime_boot_material_clear(void)
{
    js_vbc4_wipe_volatile(js_runtime_master_key_shares, sizeof(js_runtime_master_key_shares));
    js_vbc4_wipe_volatile(js_runtime_layout_digest_shares, sizeof(js_runtime_layout_digest_shares));
    js_vbc4_wipe_volatile(js_runtime_resource_key_shares, sizeof(js_runtime_resource_key_shares));
    for (int slot = 0; slot < JS_RRK_SLOTS; slot++) js_runtime_resource_key_slot_ready[slot] = 0;
    js_runtime_resource_partition_count = 0;
}

JS_LOCAL jboolean JNICALL
jsn_k7(JNIEnv *env, jclass cls, jbyteArray material)
{
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsn_k7, 1)) return JNI_FALSE;
    if (!env || !material || js_runtime_boot_material_state != 0) return JNI_FALSE;
    jsize length = (*env)->GetArrayLength(env, material);
    if (length < (jsize)(4 + 64 + 64) ||
        length > (jsize)(4 + 64 + JS_RRK_SLOTS * 32 + 4 * 33)) return JNI_FALSE;
    unsigned char *raw = (unsigned char*)malloc((size_t)length);
    if (!raw) return JNI_FALSE;
    (*env)->GetByteArrayRegion(env, material, 0, length, (jbyte*)raw);
    if ((*env)->ExceptionCheck(env)) {
        js_vbc4_wipe_volatile(raw, (size_t)length);
        free(raw);
        return JNI_FALSE;
    }
    int partition_count = raw[1] & 0xFF;
    int slot_count = raw[2] & 0xFF;
    int binding_count = raw[3] & 0xFF;
    int valid = (raw[0] == 2 || raw[0] == 3) && partition_count >= 1 && partition_count <= JS_RRK_RESOURCE_SLOTS &&
        slot_count == partition_count + 1 && binding_count >= 0 && binding_count <= 4 &&
        length == (jsize)(4 + 64 + slot_count * 32 + binding_count * 33);
    if (valid) {
        size_t binding_offset = (size_t)(4 + 64 + slot_count * 32);
        unsigned int seen_platforms = 0u;
        for (int binding = 0; binding < binding_count && valid; binding++) {
            unsigned int platform_id = raw[binding_offset++];
            unsigned int platform_bit = platform_id >= 1u && platform_id <= 4u ? 1u << platform_id : 0u;
            unsigned int nonzero = 0u;
            if (platform_bit == 0u || (seen_platforms & platform_bit) != 0u) {
                valid = 0;
                break;
            }
            seen_platforms |= platform_bit;
            for (size_t i = 0; i < 32u; i++) nonzero |= (unsigned int)raw[binding_offset + i];
            if (nonzero == 0u) valid = 0;
            binding_offset += 32u;
        }
    }
    js_runtime_boot_material_state = valid ? 1 : -1;
    if (valid) {
        js_runtime_boot_material_clear();
        js_rrk_split_runtime_value(raw + 4, js_runtime_master_key_shares);
        js_rrk_split_runtime_value(raw + 36, js_runtime_layout_digest_shares);
        const unsigned char *keys = raw + 68;
        for (int slot = 0; slot < partition_count; slot++) {
            js_rrk_split_runtime_value(keys + slot * 32, js_runtime_resource_key_shares[slot]);
            js_runtime_resource_key_slot_ready[slot] = 1;
        }
        js_rrk_split_runtime_value(keys + partition_count * 32, js_runtime_resource_key_shares[JS_RRK_ANCHOR_SLOT]);
        js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT] = 1;
        js_runtime_resource_partition_count = partition_count;
        js_runtime_boot_material_state = 2;
        /* JNI_OnLoad necessarily runs before this authenticated boot envelope
         * is installed.  Retry the optional helper registrations now that the
         * anchor slot is live, so keyed class/method bindings (notably the
         * string-encryption helper) resolve to their final renamed members. */
        if (!js_jni_register_deferred_natives(env)) {
            js_runtime_boot_material_clear();
            js_runtime_boot_material_state = -1;
            valid = 0;
        }
    } else {
        js_runtime_boot_material_clear();
    }
    js_vbc4_wipe_volatile(raw, (size_t)length);
    free(raw);
    return valid ? JNI_TRUE : JNI_FALSE;
}

JS_LOCAL jboolean JNICALL
jsn_k11(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    if (js_runtime_boot_material_state != 2 || js_runtime_resource_partition_count < 1) return JNI_FALSE;
    if (!js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT]) return JNI_FALSE;
    for (int slot = 0; slot < js_runtime_resource_partition_count; slot++) {
        if (!js_runtime_resource_key_slot_ready[slot]) return JNI_FALSE;
    }
    return JNI_TRUE;
}

JS_LOCAL jbyteArray JNICALL
jsn_k13(JNIEnv *env, jclass cls, jbyteArray encoded)
{
    (void)cls;
    if (!env || !encoded || js_runtime_boot_material_state != 2) return NULL;
    jsize raw_len = (*env)->GetArrayLength(env, encoded);
    if (raw_len <= 0 || raw_len > 64 * 1024 * 1024) return NULL;
    unsigned char *raw = (unsigned char*)malloc((size_t)raw_len);
    if (!raw) return NULL;
    (*env)->GetByteArrayRegion(env, encoded, 0, raw_len, (jbyte*)raw);
    if ((*env)->ExceptionCheck(env)) {
        js_vbc4_wipe_volatile(raw, (size_t)raw_len);
        free(raw);
        return NULL;
    }
    int plain_len = 0;
    unsigned char *plain = js_runtime_resource_decode_owned(raw, (int)raw_len, &plain_len);
    js_vbc4_wipe_volatile(raw, (size_t)raw_len);
    free(raw);
    if (!plain || plain_len < 0) {
        if (plain) {
            js_vbc4_wipe_volatile(plain, (size_t)(plain_len > 0 ? plain_len : 0));
            free(plain);
        }
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)plain_len);
    if (result && plain_len > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plain_len, (const jbyte*)plain);
    }
    js_vbc4_wipe_volatile(plain, (size_t)plain_len);
    free(plain);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return result;
}

JS_LOCAL void JNICALL
jsn_k12(JNIEnv *env, jclass cls)
{
    (void)cls;
    js_vm_abort_preload_state(env);
    js_runtime_boot_material_clear();
    js_runtime_boot_material_state = -1;
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
    if (!js_vm_call_gate_mark_loading(entryToken, path)) {
        cached = js_vm_call_gate_wait_for_program(entryToken, path);
        rls(env, resourcePath, path);
        if (!cached) js_vm_fail_closed(env, "native VM preload did not complete");
        return;
    }
    js_vm_program *program = js_vm_prepare_resource_program(env, cls, entryToken, resourcePath);
    if (program) {
        js_vm_program validation;
        memset(&validation, 0, sizeof(validation));
        if (!js_vm_build_execution_program_from_registers(program, &validation)) {
            char reason[384];
            snprintf(reason, sizeof(reason), "native VM preload validation failed for entry=%016llx err=%d reg=%d super=%d insn=%d",
                (unsigned long long)program->entry_token,
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
jsn_k9(JNIEnv *env, jclass cls, jbyteArray preload_index, jbyteArray commitments, jbyteArray startup_nonce)
{
    (void)cls;
    /* A preload attempt replaces the complete runtime catalog/session domain.
     * Drop any prior programs before accepting a new nonce so a failed retry
     * cannot leave old programs reachable under partially replaced gates. */
    js_vm_abort_preload_state(env);
    if (!preload_index || !commitments || !startup_nonce || (*env)->GetArrayLength(env, startup_nonce) != 32) {
        js_vm_fail_closed(env, "missing VM catalog payload");
        return;
    }
    jbyte startup_nonce_bytes[32] = {0};
    (*env)->GetByteArrayRegion(env, startup_nonce, 0, 32, startup_nonce_bytes);
    if ((*env)->ExceptionCheck(env)) {
        js_vbc4_wipe_volatile(startup_nonce_bytes, sizeof(startup_nonce_bytes));
        js_vm_abort_preload_state(env);
        /* Preserve the pending JNI exception; ThrowNew cannot replace it. */
        return;
    }
    if (!js_vm_install_startup_nonce((const unsigned char*)startup_nonce_bytes, 32)) {
        js_vbc4_wipe_volatile(startup_nonce_bytes, sizeof(startup_nonce_bytes));
        js_vm_abort_preload_state(env);
        js_vm_fail_closed(env, "invalid VM startup nonce");
        return;
    }
    js_vbc4_wipe_volatile(startup_nonce_bytes, sizeof(startup_nonce_bytes));
    int index_len = (*env)->GetArrayLength(env, preload_index);
    int commitment_len = (*env)->GetArrayLength(env, commitments);
    jbyte *index_raw = index_len > 0 ? (*env)->GetByteArrayElements(env, preload_index, NULL) : NULL;
    jbyte *commitment_raw = commitment_len > 0 ? (*env)->GetByteArrayElements(env, commitments, NULL) : NULL;
    unsigned char *index_bytes = index_len > 0 ? (unsigned char*)malloc((size_t)index_len) : NULL;
    if (!index_raw || !commitment_raw || !index_bytes) {
        if (index_raw) (*env)->ReleaseByteArrayElements(env, preload_index, index_raw, JNI_ABORT);
        if (commitment_raw) (*env)->ReleaseByteArrayElements(env, commitments, commitment_raw, JNI_ABORT);
        if (index_bytes) free(index_bytes);
        js_vm_abort_preload_state(env);
        js_vm_fail_closed(env, "invalid VM catalog payload");
        return;
    }
    memcpy(index_bytes, index_raw, (size_t)index_len);
    int commitments_ok = js_vm_commitments_install((const unsigned char*)commitment_raw, commitment_len);
    (*env)->ReleaseByteArrayElements(env, preload_index, index_raw, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, commitments, commitment_raw, JNI_ABORT);
    if (!commitments_ok || index_len <= 0) {
        js_vbc4_wipe_volatile(index_bytes, (size_t)(index_len > 0 ? index_len : 0));
        free(index_bytes);
        js_vm_abort_preload_state(env);
        js_vm_fail_closed(env, "invalid VM catalog commitments");
        return;
    }
    int line_start = 0;
    for (int i = 0; i <= index_len; i++) {
        if (i != index_len && index_bytes[i] != '\n' && index_bytes[i] != '\r') continue;
        int line_end = i;
        while (line_start < line_end && (index_bytes[line_start] == ' ' || index_bytes[line_start] == '\t')) line_start++;
        while (line_end > line_start && (index_bytes[line_end - 1] == ' ' || index_bytes[line_end - 1] == '\t')) line_end--;
        if (line_end > line_start) {
            int sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1, sep5 = -1, sep6 = -1, sep7 = -1, sep8 = -1;
            for (int p = line_start; p < line_end; p++) {
                if (index_bytes[p] != '|') continue;
                if (sep1 < 0) sep1 = p;
                else if (sep2 < 0) sep2 = p;
                else if (sep3 < 0) sep3 = p;
                else if (sep4 < 0) sep4 = p;
                else if (sep5 < 0) sep5 = p;
                else if (sep6 < 0) sep6 = p;
                else if (sep7 < 0) sep7 = p;
                else { sep8 = p; break; }
            }
            if (sep1 == line_start + 1 && index_bytes[line_start] == 'A') {
                while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
                line_start = i + 1;
                continue;
            }
            if (sep1 <= line_start || sep1 + 1 >= line_end || sep1 - line_start > 16) {
                js_vm_abort_preload_state(env);
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
                    js_vm_abort_preload_state(env);
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
            char *token_text = NULL;
            char *shard_text = NULL;
            char *mesh_text = NULL;
            char *profile_text = NULL;
            char *auth_text = NULL;
            uint32_t expected_profile = 0u;
            uint32_t shard_count = 0;
            if (sep2 > 0 && sep3 > 0) {
                token_text = js_substr_dup((const char*)index_bytes + line_start, (size_t)(sep1 - line_start));
                resource_path = js_substr_dup((const char*)index_bytes + sep1 + 1, (size_t)(sep2 - sep1 - 1));
                manifest_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(sep3 - sep2 - 1));
                int shard_end = sep4 > 0 ? sep4 : line_end;
                shard_text = js_substr_dup((const char*)index_bytes + sep3 + 1, (size_t)(shard_end - sep3 - 1));
                if (!shard_text || !js_parse_u32_token(shard_text, &shard_count)) shard_count = 0;
                if (sep6 > 0 && sep4 > 0 && sep5 > sep4 && sep6 > sep5) {
                    mesh_text = js_substr_dup((const char*)index_bytes + sep4 + 1, (size_t)(sep5 - sep4 - 1));
                    profile_text = js_substr_dup((const char*)index_bytes + sep5 + 1, (size_t)(sep6 - sep5 - 1));
                    int auth_end = sep7 > 0 ? sep7 : line_end;
                    auth_text = js_substr_dup((const char*)index_bytes + sep6 + 1, (size_t)(auth_end - sep6 - 1));
                    if (!profile_text || !js_parse_hex_u32_token(profile_text, &expected_profile)) {
                        if (token_text) { js_vbc4_wipe_volatile(token_text, strlen(token_text)); free(token_text); }
                        if (shard_text) { js_vbc4_wipe_volatile(shard_text, strlen(shard_text)); free(shard_text); }
                        if (mesh_text) { js_vbc4_wipe_volatile(mesh_text, strlen(mesh_text)); free(mesh_text); }
                        if (profile_text) { js_vbc4_wipe_volatile(profile_text, strlen(profile_text)); free(profile_text); }
                        if (auth_text) { js_vbc4_wipe_volatile(auth_text, strlen(auth_text)); free(auth_text); }
                        if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); }
                        if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                        if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                        if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                        js_vm_abort_preload_state(env);
                        js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                        free(index_bytes);
                        js_vm_fail_closed(env, "malformed VM preload profile");
                        return;
                    }
                    if (sep7 > 0) {
                        int binding_resource_end = sep8 > 0 ? sep8 : line_end;
                        binding_resource_path = js_substr_dup((const char*)index_bytes + sep7 + 1, (size_t)(binding_resource_end - sep7 - 1));
                        if (sep8 > 0) binding_manifest_path = js_substr_dup((const char*)index_bytes + sep8 + 1, (size_t)(line_end - sep8 - 1));
                    }
                    if (!js_vm_preload_entry_auth_matches(token_text, resource_path, manifest_path, shard_text, mesh_text, profile_text, auth_text)) {
                        if (token_text) { js_vbc4_wipe_volatile(token_text, strlen(token_text)); free(token_text); }
                        if (shard_text) { js_vbc4_wipe_volatile(shard_text, strlen(shard_text)); free(shard_text); }
                        if (mesh_text) { js_vbc4_wipe_volatile(mesh_text, strlen(mesh_text)); free(mesh_text); }
                        if (profile_text) { js_vbc4_wipe_volatile(profile_text, strlen(profile_text)); free(profile_text); }
                        if (auth_text) { js_vbc4_wipe_volatile(auth_text, strlen(auth_text)); free(auth_text); }
                        if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); }
                        if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                        if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                        if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                        js_vm_abort_preload_state(env);
                        js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                        free(index_bytes);
                        js_vm_fail_closed(env, "invalid VM preload profile auth");
                        return;
                    }
                } else if (sep4 > 0) {
                    int binding_resource_end = sep5 > 0 ? sep5 : line_end;
                    binding_resource_path = js_substr_dup((const char*)index_bytes + sep4 + 1, (size_t)(binding_resource_end - sep4 - 1));
                    if (sep5 > 0) binding_manifest_path = js_substr_dup((const char*)index_bytes + sep5 + 1, (size_t)(line_end - sep5 - 1));
                }
            } else {
                resource_path = js_substr_dup((const char*)index_bytes + sep1 + 1, (size_t)(line_end - sep1 - 1));
            }
            const char *preload_binding_path = binding_resource_path && binding_resource_path[0] ? binding_resource_path : resource_path;
            const char *preload_binding_manifest = binding_manifest_path && binding_manifest_path[0] ? binding_manifest_path : manifest_path;
            if (!resource_path || (sep2 > 0 && sep3 > 0 && (!manifest_path || shard_count < 2))) {
                if (token_text) { js_vbc4_wipe_volatile(token_text, strlen(token_text)); free(token_text); }
                if (shard_text) { js_vbc4_wipe_volatile(shard_text, strlen(shard_text)); free(shard_text); }
                if (mesh_text) { js_vbc4_wipe_volatile(mesh_text, strlen(mesh_text)); free(mesh_text); }
                if (profile_text) { js_vbc4_wipe_volatile(profile_text, strlen(profile_text)); free(profile_text); }
                if (auth_text) { js_vbc4_wipe_volatile(auth_text, strlen(auth_text)); free(auth_text); }
                if (resource_path) { js_vbc4_wipe_volatile(resource_path, strlen(resource_path)); free(resource_path); }
                if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                js_vm_abort_preload_state(env);
                js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
                free(index_bytes);
                js_vm_fail_closed(env, NULL);
                return;
            }
            if (manifest_path) js_vm_shared_dispatch_mix_preload((jlong)token, preload_binding_path, preload_binding_manifest, shard_count);
            /* On-demand unseal: program bytes are fetched, authenticated,
             * parsed and validated at first execution through
             * js_vm_preload_indexed_program_on_demand. Boot only authenticates
             * the index and registers the call gates, so startup cost stays
             * proportional to the methods actually exercised. */
            if (token_text) { js_vbc4_wipe_volatile(token_text, strlen(token_text)); free(token_text); token_text = NULL; }
            if (shard_text) { js_vbc4_wipe_volatile(shard_text, strlen(shard_text)); free(shard_text); shard_text = NULL; }
            if (mesh_text) { js_vbc4_wipe_volatile(mesh_text, strlen(mesh_text)); free(mesh_text); mesh_text = NULL; }
            if (profile_text) { js_vbc4_wipe_volatile(profile_text, strlen(profile_text)); free(profile_text); profile_text = NULL; }
            if (auth_text) { js_vbc4_wipe_volatile(auth_text, strlen(auth_text)); free(auth_text); auth_text = NULL; }
            if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); manifest_path = NULL; }
            js_vbc4_wipe_volatile(resource_path, strlen(resource_path));
            free(resource_path);
            resource_path = NULL;
            if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); binding_resource_path = NULL; }
            if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); binding_manifest_path = NULL; }
        }
        while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
        line_start = i + 1;
    }
    if (!js_vm_register_preload_index_entries(index_bytes, index_len)) {
        js_vm_abort_preload_state(env);
        js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
        free(index_bytes);
        js_vm_fail_closed(env, "VM catalog registration failed");
        return;
    }
    /* Keep the on-demand channel open after boot: the flag now means "catalog
     * registered, lazy unseal allowed". It is only cleared on process unload. */
    js_vm_preload_in_progress = 1;
    js_vbc4_wipe_volatile(index_bytes, (size_t)index_len);
    free(index_bytes);
}
/* Keyed binding identity: HMAC-SHA256(anchorKey, "jsb1" || value)[0..8] as 16
 * lowercase hex chars. Mirrors the Kotlin build-time and Java runtime mirrors;
 * without the resident anchor key the identity cannot be recomputed statically. */
static int js_sealed_binding_key(const char *value, size_t value_len, char out_hex[17]) {
    if (!value || !js_runtime_resource_key_slot_ready[JS_RRK_ANCHOR_SLOT]) return 0;
    static const unsigned char domain[] = "jsb1";
    static const char hexdig[] = "0123456789abcdef";
    unsigned char root[32];
    unsigned char digest[32];
    const unsigned char *parts[2];
    int lens[2];
    parts[0] = domain;
    lens[0] = (int)(sizeof(domain) - 1);
    parts[1] = (const unsigned char*)value;
    lens[1] = (int)value_len;
    js_rrk_xor_assemble(&js_runtime_resource_key_shares[JS_RRK_ANCHOR_SLOT][0][0], JS_RRK_SHARE_COUNT, root);
    js_hmac_sha256_with_key(root, 32, parts, lens, 2, digest);
    js_vbc4_wipe_volatile(root, sizeof(root));
    for (int i = 0; i < 8; i++) {
        out_hex[i * 2] = hexdig[(digest[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hexdig[digest[i] & 0xF];
    }
    out_hex[16] = 0;
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    return 1;
}

JS_LOCAL jstring JNICALL jsn_k15(JNIEnv *env, jclass cls, jbyteArray value_array) {
    (void)cls;
    if (!js_vm_sensitive_path_guard(env, (const void*)jsn_k15, 1)) return NULL;
    if (!env || !value_array) return NULL;
    jsize value_len = (*env)->GetArrayLength(env, value_array);
    if (value_len < 1 || value_len > 1024 * 1024) return NULL;
    unsigned char *value = (unsigned char*)malloc((size_t)value_len);
    char out_hex[17] = {0};
    jstring result = NULL;
    if (!value) return NULL;
    (*env)->GetByteArrayRegion(env, value_array, 0, value_len, (jbyte*)value);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    if (!js_sealed_binding_key((const char*)value, (size_t)value_len, out_hex)) {
        js_vm_throw_new(env, "java/lang/SecurityException", "native binding key unavailable");
        goto cleanup;
    }
    result = (*env)->NewStringUTF(env, out_hex);

cleanup:
    js_vbc4_wipe_volatile(value, (size_t)value_len);
    free(value);
    js_vbc4_wipe_volatile(out_hex, sizeof(out_hex));
    return result;
}

JS_HIDDEN char* js_lookup_bound_class(JNIEnv *env, const char *original) {
    if (!original) return NULL;
    char *loader_owner = js_helper_owner("Jni", "Micro", "kernel", "Helper");
    int is_loader_owner = loader_owner && !strcmp(original, loader_owner);
    free(loader_owner);
    if (is_loader_owner) {
        char *loader = js_first_loader_owner_from_property(env);
        if (loader && loader[0]) return loader;
        free(loader);
    }
    char original_key[17];
    if (!js_sealed_binding_key(original, strlen(original), original_key)) return NULL;
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
    size_t material_len = strlen(original_class) + 1 + strlen(method_name) + 1 + strlen(signature);
    char *material = (char*)malloc(material_len + 1);
    if (!material) return NULL;
    snprintf(material, material_len + 1, "%s#%s#%s", original_class, method_name, signature);
    char lookup_key[17];
    int keyed = js_sealed_binding_key(material, material_len, lookup_key);
    js_vbc4_wipe_volatile(material, material_len + 1);
    free(material);
    if (!keyed) return NULL;
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

JS_HIDDEN char* js_lookup_bound_field(JNIEnv *env, const char *original_class, const char *field_name, const char *descriptor) {
    if (!original_class || !field_name || !descriptor) return NULL;
    size_t material_len = strlen(original_class) + 1 + strlen(field_name) + 1 + strlen(descriptor);
    char *material = (char*)malloc(material_len + 1);
    if (!material) return NULL;
    snprintf(material, material_len + 1, "%s#%s#%s", original_class, field_name, descriptor);
    char lookup_key[17];
    int keyed = js_sealed_binding_key(material, material_len, lookup_key);
    js_vbc4_wipe_volatile(material, material_len + 1);
    free(material);
    if (!keyed) return NULL;
    char *bindings = sys_prop(env, "j.f");
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
    js_runtime_boot_material_clear();
    js_runtime_boot_material_state = 0;
    js_vm_clear_startup_nonce();
    if (env) js_jni_cache_destroy(env);
}

/* END MOVED JS_HELPERS CORE */
