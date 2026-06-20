#include "js_jni_runtime.h"
#include "js_antidebug.h"
#include "js_vm_resource.h"

#include <stdlib.h>
#include <string.h>

JS_HIDDEN js_jni_cache_state js_jni_cache;

extern jint JNICALL jsn_k0(JNIEnv* env, jclass clazz, jstring platform);
extern jint JNICALL jsn_k1(JNIEnv* env, jclass clazz, jbyteArray data, jbyteArray expected_mac);
extern jint JNICALL jsn_k3(JNIEnv* env, jclass clazz);
extern jbyteArray JNICALL jsn_k4(JNIEnv* env, jclass clazz, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr);
extern jstring JNICALL jsn_k5(JNIEnv* env, jclass clazz);
extern jlong JNICALL jsn_k6(JNIEnv* env, jclass clazz);
JS_HIDDEN void JNICALL jsn_k7(JNIEnv *env, jclass cls, jbyteArray keyArr);
JS_HIDDEN void JNICALL jsn_k9(JNIEnv *env, jclass cls);
JS_HIDDEN jbyteArray JNICALL jsn_k10(JNIEnv *env, jclass cls, jbyteArray keyIdArr, jbyteArray saltArr, jint length);
JS_HIDDEN void JNICALL jsn_r0(JNIEnv *env, jclass cls, jstring jdl, jstring jresp);
JS_HIDDEN void JNICALL jsn_r1(JNIEnv *env, jclass cls, jstring jdm, jstring jresp);
JS_HIDDEN void JNICALL jsn_r2(JNIEnv *env, jclass cls, jstring jresp);
JS_HIDDEN void JNICALL jsn_r3(JNIEnv *env, jclass cls, jstring jpl);
JS_HIDDEN jstring JNICALL jsn_r11(JNIEnv *env, jclass cls, jbyteArray encodedBytes);
JS_HIDDEN jstring JNICALL jsn_r12(JNIEnv *env, jclass cls, jstring encodedB64);
JS_HIDDEN jstring JNICALL jsn_r13(JNIEnv *env, jclass cls, jstring encoded);
JS_HIDDEN jstring JNICALL jsn_r16(JNIEnv *env, jclass cls, jstring bindingSource, jstring salt);
JS_HIDDEN void JNICALL jsn_r17(JNIEnv *env, jclass cls, jstring expectedToken, jstring bindingSource, jstring salt);
JS_HIDDEN jobject JNICALL jsn_r20(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath, jobjectArray args);
JS_HIDDEN jbyteArray JNICALL jsn_r21(JNIEnv *env, jclass cls, jbyteArray payload, jint seed, jint flags);
JS_HIDDEN jobject JNICALL jsn_r22(JNIEnv *env, jclass cls, jlong entryToken, jobjectArray args);
JS_HIDDEN void JNICALL jsn_r23(JNIEnv *env, jclass cls, jlong entryToken);
JS_HIDDEN void JNICALL jsn_r24(JNIEnv *env, jclass cls, jlong entryToken, jint arg0);

static jclass js_jni_cache_global_class(JNIEnv *env, const char *name) {
    jclass local = (*env)->FindClass(env, name);
    if ((*env)->ExceptionCheck(env) || !local) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    jclass global = (jclass)(*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if ((*env)->ExceptionCheck(env) || !global) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    return global;
}

static int js_jni_cache_require_member(JNIEnv *env, const void *member) {
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return member != NULL;
}

JS_HIDDEN void js_jni_cache_destroy(JNIEnv *env) {
    if (!env) {
        memset(&js_jni_cache, 0, sizeof(js_jni_cache));
        return;
    }
#define JS_JNI_DELETE_GLOBAL(field) do { if (js_jni_cache.field) (*env)->DeleteGlobalRef(env, js_jni_cache.field); } while (0)
    JS_JNI_DELETE_GLOBAL(object_class);
    JS_JNI_DELETE_GLOBAL(string_class);
    JS_JNI_DELETE_GLOBAL(class_loader_class);
    JS_JNI_DELETE_GLOBAL(byte_array_class);
    JS_JNI_DELETE_GLOBAL(class_class);
    JS_JNI_DELETE_GLOBAL(thread_class);
    JS_JNI_DELETE_GLOBAL(input_stream_class);
    JS_JNI_DELETE_GLOBAL(string_builder_class);
    JS_JNI_DELETE_GLOBAL(runtime_exception_class);
    JS_JNI_DELETE_GLOBAL(security_exception_class);
    JS_JNI_DELETE_GLOBAL(throwable_class);
    JS_JNI_DELETE_GLOBAL(stack_trace_element_class);
    JS_JNI_DELETE_GLOBAL(reflect_array_class);
    JS_JNI_DELETE_GLOBAL(system_class);
    JS_JNI_DELETE_GLOBAL(integer_class);
    JS_JNI_DELETE_GLOBAL(boolean_class);
    JS_JNI_DELETE_GLOBAL(byte_class);
    JS_JNI_DELETE_GLOBAL(short_class);
    JS_JNI_DELETE_GLOBAL(character_class);
    JS_JNI_DELETE_GLOBAL(long_class);
    JS_JNI_DELETE_GLOBAL(float_class);
    JS_JNI_DELETE_GLOBAL(double_class);
    JS_JNI_DELETE_GLOBAL(void_class);
#undef JS_JNI_DELETE_GLOBAL
    memset(&js_jni_cache, 0, sizeof(js_jni_cache));
}

JS_HIDDEN int js_jni_cache_init(JNIEnv *env) {
    if (!env) return 0;
    memset(&js_jni_cache, 0, sizeof(js_jni_cache));
#define JS_JNI_CLASS(field, name) do { js_jni_cache.field = js_jni_cache_global_class(env, name); if (!js_jni_cache.field) goto fail; } while (0)
#define JS_JNI_METHOD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetMethodID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)
#define JS_JNI_STATIC_METHOD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetStaticMethodID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)
#define JS_JNI_STATIC_FIELD(field, cls, name, sig) do { js_jni_cache.field = (*env)->GetStaticFieldID(env, js_jni_cache.cls, name, sig); if (!js_jni_cache_require_member(env, js_jni_cache.field)) goto fail; } while (0)

    JS_JNI_CLASS(object_class, "java/lang/Object");
    JS_JNI_CLASS(string_class, "java/lang/String");
    JS_JNI_CLASS(class_loader_class, "java/lang/ClassLoader");
    JS_JNI_CLASS(byte_array_class, "[B");
    JS_JNI_CLASS(class_class, "java/lang/Class");
    JS_JNI_CLASS(thread_class, "java/lang/Thread");
    JS_JNI_CLASS(input_stream_class, "java/io/InputStream");
    JS_JNI_CLASS(string_builder_class, "java/lang/StringBuilder");
    JS_JNI_CLASS(runtime_exception_class, "java/lang/RuntimeException");
    JS_JNI_CLASS(security_exception_class, "java/lang/SecurityException");
    JS_JNI_CLASS(throwable_class, "java/lang/Throwable");
    JS_JNI_CLASS(reflect_array_class, "java/lang/reflect/Array");
    JS_JNI_CLASS(system_class, "java/lang/System");
    JS_JNI_CLASS(integer_class, "java/lang/Integer");
    JS_JNI_CLASS(boolean_class, "java/lang/Boolean");
    JS_JNI_CLASS(byte_class, "java/lang/Byte");
    JS_JNI_CLASS(short_class, "java/lang/Short");
    JS_JNI_CLASS(character_class, "java/lang/Character");
    JS_JNI_CLASS(long_class, "java/lang/Long");
    JS_JNI_CLASS(float_class, "java/lang/Float");
    JS_JNI_CLASS(double_class, "java/lang/Double");
    JS_JNI_CLASS(void_class, "java/lang/Void");

    JS_JNI_METHOD(class_loader_get_resource_as_stream, class_loader_class, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    JS_JNI_METHOD(class_loader_load_class, class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    JS_JNI_METHOD(class_loader_define_class, class_loader_class, "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;");
    JS_JNI_METHOD(class_loader_define_class_pd, class_loader_class, "defineClass", "(Ljava/lang/String;[BIILjava/security/ProtectionDomain;)Ljava/lang/Class;");
    JS_JNI_METHOD(class_get_class_loader, class_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
    JS_JNI_METHOD(class_get_name, class_class, "getName", "()Ljava/lang/String;");
    JS_JNI_METHOD(class_get_resource_as_stream, class_class, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    JS_JNI_METHOD(class_is_array, class_class, "isArray", "()Z");
    JS_JNI_METHOD(class_get_component_type, class_class, "getComponentType", "()Ljava/lang/Class;");
    JS_JNI_STATIC_METHOD(thread_current_thread, thread_class, "currentThread", "()Ljava/lang/Thread;");
    JS_JNI_METHOD(thread_get_context_class_loader, thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    JS_JNI_METHOD(input_stream_read_all_bytes, input_stream_class, "readAllBytes", "()[B");
    JS_JNI_METHOD(input_stream_close, input_stream_class, "close", "()V");
    JS_JNI_METHOD(string_builder_init, string_builder_class, "<init>", "()V");
    JS_JNI_METHOD(string_builder_append_string, string_builder_class, "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
    JS_JNI_METHOD(string_builder_to_string, string_builder_class, "toString", "()Ljava/lang/String;");
    JS_JNI_METHOD(runtime_exception_init, runtime_exception_class, "<init>", "(Ljava/lang/String;)V");
    {
        jclass local_stack_trace_element = (*env)->FindClass(env, "java/lang/StackTraceElement");
        if ((*env)->ExceptionCheck(env) || !local_stack_trace_element) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        } else {
            js_jni_cache.stack_trace_element_class = (jclass)(*env)->NewGlobalRef(env, local_stack_trace_element);
            (*env)->DeleteLocalRef(env, local_stack_trace_element);
            if ((*env)->ExceptionCheck(env) || !js_jni_cache.stack_trace_element_class) {
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                js_jni_cache.stack_trace_element_class = NULL;
            } else {
                js_jni_cache.throwable_set_stack_trace = (*env)->GetMethodID(env, js_jni_cache.throwable_class, "setStackTrace", "([Ljava/lang/StackTraceElement;)V");
                if ((*env)->ExceptionCheck(env) || !js_jni_cache.throwable_set_stack_trace) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); js_jni_cache.throwable_set_stack_trace = NULL; }
                js_jni_cache.stack_trace_element_init = (*env)->GetMethodID(env, js_jni_cache.stack_trace_element_class, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");
                if ((*env)->ExceptionCheck(env) || !js_jni_cache.stack_trace_element_init) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); js_jni_cache.stack_trace_element_init = NULL; }
            }
        }
    }
    JS_JNI_METHOD(integer_int_value, integer_class, "intValue", "()I");
    JS_JNI_METHOD(boolean_boolean_value, boolean_class, "booleanValue", "()Z");
    JS_JNI_METHOD(byte_byte_value, byte_class, "byteValue", "()B");
    JS_JNI_METHOD(short_short_value, short_class, "shortValue", "()S");
    JS_JNI_METHOD(character_char_value, character_class, "charValue", "()C");
    JS_JNI_METHOD(long_long_value, long_class, "longValue", "()J");
    JS_JNI_METHOD(float_float_value, float_class, "floatValue", "()F");
    JS_JNI_METHOD(double_double_value, double_class, "doubleValue", "()D");
    JS_JNI_STATIC_METHOD(integer_value_of, integer_class, "valueOf", "(I)Ljava/lang/Integer;");
    JS_JNI_STATIC_METHOD(boolean_value_of, boolean_class, "valueOf", "(Z)Ljava/lang/Boolean;");
    JS_JNI_STATIC_METHOD(byte_value_of, byte_class, "valueOf", "(B)Ljava/lang/Byte;");
    JS_JNI_STATIC_METHOD(short_value_of, short_class, "valueOf", "(S)Ljava/lang/Short;");
    JS_JNI_STATIC_METHOD(character_value_of, character_class, "valueOf", "(C)Ljava/lang/Character;");
    JS_JNI_STATIC_METHOD(long_value_of, long_class, "valueOf", "(J)Ljava/lang/Long;");
    JS_JNI_STATIC_METHOD(float_value_of, float_class, "valueOf", "(F)Ljava/lang/Float;");
    JS_JNI_STATIC_METHOD(double_value_of, double_class, "valueOf", "(D)Ljava/lang/Double;");
    JS_JNI_STATIC_METHOD(string_value_of_object, string_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_int, string_class, "valueOf", "(I)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_long, string_class, "valueOf", "(J)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_float, string_class, "valueOf", "(F)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_double, string_class, "valueOf", "(D)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_boolean, string_class, "valueOf", "(Z)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(string_value_of_char, string_class, "valueOf", "(C)Ljava/lang/String;");
    JS_JNI_STATIC_METHOD(reflect_array_new_instance_dims, reflect_array_class, "newInstance", "(Ljava/lang/Class;[I)Ljava/lang/Object;");
    JS_JNI_STATIC_METHOD(reflect_array_new_instance_len, reflect_array_class, "newInstance", "(Ljava/lang/Class;I)Ljava/lang/Object;");
    JS_JNI_STATIC_METHOD(system_arraycopy, system_class, "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V");
    JS_JNI_STATIC_FIELD(integer_type_field, integer_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(boolean_type_field, boolean_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(byte_type_field, byte_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(short_type_field, short_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(character_type_field, character_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(long_type_field, long_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(float_type_field, float_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(double_type_field, double_class, "TYPE", "Ljava/lang/Class;");
    JS_JNI_STATIC_FIELD(void_type_field, void_class, "TYPE", "Ljava/lang/Class;");

    js_jni_cache.initialized = 1;
#undef JS_JNI_CLASS
#undef JS_JNI_METHOD
#undef JS_JNI_STATIC_METHOD
#undef JS_JNI_STATIC_FIELD
    return 1;
fail:
#undef JS_JNI_CLASS
#undef JS_JNI_METHOD
#undef JS_JNI_STATIC_METHOD
#undef JS_JNI_STATIC_FIELD
    js_jni_cache_destroy(env);
    return 0;
}

static int js_register_natives(JNIEnv *env, const char *class_name, const JNINativeMethod *methods, int count, int required) {
    jclass cls = js_vm_find_registration_class(env, class_name);
    if (!cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return required ? 0 : 1;
    }
    if ((*env)->RegisterNatives(env, cls, methods, count) != 0) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return required ? 0 : 1;
    }
    return 1;
}

static int js_register_bound_natives(JNIEnv *env, const char *class_name, const JNINativeMethod *methods, int count, int required) {
    char *mapped = js_lookup_bound_class(env, class_name);
    const char *effective_name = mapped && mapped[0] ? mapped : class_name;
    JNINativeMethod *effective_methods = NULL;
    char **owned_method_names = NULL;
    const JNINativeMethod *methods_to_register = methods;
    if (count > 0) {
        effective_methods = (JNINativeMethod*)calloc((size_t)count, sizeof(JNINativeMethod));
        owned_method_names = (char**)calloc((size_t)count, sizeof(char*));
        if (effective_methods && owned_method_names) {
            for (int i = 0; i < count; i++) {
                effective_methods[i] = methods[i];
                char *method_name = js_lookup_bound_method(env, class_name, methods[i].name, methods[i].signature);
                if (method_name && method_name[0]) {
                    effective_methods[i].name = method_name;
                    owned_method_names[i] = method_name;
                } else {
                    free(method_name);
                }
            }
            methods_to_register = effective_methods;
        }
    }
    int ok = js_register_natives(env, effective_name, methods_to_register, count, required);
    if (owned_method_names) {
        for (int i = 0; i < count; i++) free(owned_method_names[i]);
    }
    free(owned_method_names);
    free(effective_methods);
    free(mapped);
    return ok;
}

static int js_register_native_group(JNIEnv *env, char *owner, JNINativeMethod *methods, int count, int required) {
    int ready = owner != NULL;
    for (int i = 0; ready && i < count; i++) {
        if (!methods[i].name) ready = 0;
    }
    int ok = ready ? js_register_bound_natives(env, owner, methods, count, required) : (required ? 0 : 1);
    for (int i = 0; i < count; i++) free((void*)methods[i].name);
    free(owner);
    return ok;
}

static int js_register_all_natives(JNIEnv *env) {
    JNINativeMethod jni_microkernel_methods[] = {
        {js_native_name("In", "it", ""), "(Ljava/lang/String;)I", (void*)jsn_k0},
        {js_native_name("Ver", "ify", ""), "([B[B)I", (void*)jsn_k1},
        {js_native_name("Heart", "beat", ""), "()I", (void*)jsn_k3},
        {js_native_name("Get", "Ver", "sion"), "()Ljava/lang/String;", (void*)jsn_k5},
        {js_native_name("Get", "Boot", "Token"), "()J", (void*)jsn_k6},
        {js_native_name("Install", "RuntimeResource", "Key"), "([B)V", (void*)jsn_k7},
        {js_native_name("Preload", "Runtime", "Resources"), "()V", (void*)jsn_k9},
        {js_native_name("De", "crypt", "Aes"), "([B[B[B)[B", (void*)jsn_k4},
        {js_native_name("Derive", "ClassEncryption", "Key"), "([B[BI)[B", (void*)jsn_k10},
        {js_native_name("Ex", "ecuteVm", "Resource"), "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;", (void*)jsn_r20},
        {js_native_name("Ex", "ecuteVmResource", "ByToken"), "(J[Ljava/lang/Object;)Ljava/lang/Object;", (void*)jsn_r22},
        {js_native_name("Ex", "ecuteVmResource", "Void"), "(J)V", (void*)jsn_r23},
        {js_native_name("Ex", "ecuteVmResourceInt", "Void"), "(JI)V", (void*)jsn_r24},
    };
    if (!js_register_native_group(env, js_helper_owner("Jni", "Micro", "kernel", "Helper"), jni_microkernel_methods, (int)(sizeof(jni_microkernel_methods) / sizeof(jni_microkernel_methods[0])), 1)) return 0;

    JNINativeMethod anti_instrumentation_methods[] = {{js_native_name("Check", "Instr", "umentation"), "(Ljava/lang/String;Ljava/lang/String;)V", (void*)jsn_r0}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiInstr", "umentation", "Helper"), anti_instrumentation_methods, 1, 0)) return 0;

    JNINativeMethod anti_jvmti_methods[] = {{js_native_name("Check", "JvmTi", "Agents"), "(Ljava/lang/String;Ljava/lang/String;)V", (void*)jsn_r1}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiJvm", "Ti", "Helper"), anti_jvmti_methods, 1, 0)) return 0;

    JNINativeMethod anti_bytebuddy_methods[] = {{js_native_name("Check", "Byte", "Buddy"), "(Ljava/lang/String;)V", (void*)jsn_r2}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiByte", "Buddy", "Helper"), anti_bytebuddy_methods, 1, 0)) return 0;

    JNINativeMethod anti_dump_runtime_methods[] = {{js_native_name("Init", "ialize", "Protection"), "(Ljava/lang/String;)V", (void*)jsn_r3}};
    if (!js_register_native_group(env, js_helper_owner("An", "tiDump", "Runtime", "Helper"), anti_dump_runtime_methods, 1, 0)) return 0;

    JNINativeMethod anti_dump_methods[] = {
        {js_native_name("Build", "String", ""), "([B)Ljava/lang/String;", (void*)jsn_r11},
        {js_native_name("Build", "StringFrom", "B64"), "(Ljava/lang/String;)Ljava/lang/String;", (void*)jsn_r12},
        {js_native_name("Decode", "String", ""), "(Ljava/lang/String;)Ljava/lang/String;", (void*)jsn_r13},
    };
    if (!js_register_native_group(env, js_helper_owner("An", "tiDump", "", "Helper"), anti_dump_methods, 3, 0)) return 0;

    JNINativeMethod string_encryption_methods[] = {{js_native_name("Decode", "String", ""), "([BII)[B", (void*)jsn_r21}};
    if (!js_register_native_group(env, js_helper_owner("String", "Encryption", "", "Helper"), string_encryption_methods, 1, 0)) return 0;
    JNINativeMethod environment_methods[] = {
        {js_native_name("Derive", "Key", ""), "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)jsn_r16},
        {js_native_name("Verify", "Environment", ""), "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", (void*)jsn_r17},
    };
    if (!js_register_native_group(env, js_helper_owner("Environment", "Binding", "", "Helper"), environment_methods, 2, 0)) return 0;

    return 1;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    js_native_anti_dump_harden();
    js_vm_cache_lock_init();
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        return JNI_ERR;
    }
    if (!js_jni_cache_init(env)) return JNI_ERR;
    int ok = js_register_all_natives(env);
    if (ok) js_vm_mark_hot_integrity_baseline_clean();
    if (!ok) js_jni_cache_destroy(env);
    return ok ? JNI_VERSION_1_6 : JNI_ERR;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) env = NULL;
    js_runtime_on_unload_cleanup(env);
    js_vm_cache_lock_destroy();
}
