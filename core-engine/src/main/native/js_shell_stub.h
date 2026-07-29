#ifndef JS_SHELL_STUB_H
#define JS_SHELL_STUB_H

#include <jni.h>

jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);
void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved);

#endif