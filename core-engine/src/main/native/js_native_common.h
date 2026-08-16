#ifndef JS_NATIVE_COMMON_H
#define JS_NATIVE_COMMON_H

#include <jni.h>
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#define JS_HIDDEN
#define JS_EXPORT __declspec(dllexport)
#else
#define JS_HIDDEN __attribute__((visibility("hidden")))
#define JS_EXPORT __attribute__((visibility("default")))
#endif

#include "js_protected_section.h"

#ifndef JS_PROTECTED
#if JS_PROTECTED_SECTION_ENABLED
#define JS_PROTECTED __attribute__((noinline, section(JS_PROTECTED_SECTION_NAME)))
#else
#define JS_PROTECTED __attribute__((noinline))
#endif
#endif

JS_HIDDEN char* js_strdup(const char *s);
JS_HIDDEN char* js_substr_dup(const char *start, size_t len);
JS_HIDDEN unsigned int fnv1a(const unsigned char *data, int len);
JS_HIDDEN const char* j2c(JNIEnv *env, jstring js);
JS_HIDDEN void rls(JNIEnv *env, jstring js, const char *s);
JS_HIDDEN int js_pending_exception(JNIEnv *env);
JS_HIDDEN void js_clear_pending_exception(JNIEnv *env);
JS_HIDDEN int starts(const char *s, const char *p);
JS_HIDDEN int contains(const char *s, const char *sub);
JS_HIDDEN char* js_join_parts(const char *first, ...);
JS_HIDDEN char* js_helper_owner(const char *a, const char *b, const char *c, const char *d);
JS_HIDDEN char* js_native_name(const char *a, const char *b, const char *c);
JS_HIDDEN char* js_native_name_full(const char *name);

#endif
