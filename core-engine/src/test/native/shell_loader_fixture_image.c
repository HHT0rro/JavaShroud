#include "js_jni_runtime.h"

#if defined(_WIN32)
#include <windows.h>
#define JS_FIXTURE_EXPORT __declspec(dllexport)
#else
#define JS_FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

static const js_native_abi_table JS_FIXTURE_ABI = {
    JS_NATIVE_ABI_TABLE_VERSION,
};

JS_FIXTURE_EXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_8;
}

JS_FIXTURE_EXPORT void JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
}

JS_FIXTURE_EXPORT const js_native_abi_table *js_native_abi_table_v1(void) {
    return &JS_FIXTURE_ABI;
}

#if defined(_WIN32)
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
#endif
