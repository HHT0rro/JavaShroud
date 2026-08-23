#include "js_native_common.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

JS_HIDDEN char* js_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *copy = (char*)malloc(len);
    if (copy) memcpy(copy, s, len);
    return copy;
}

JS_HIDDEN char* js_substr_dup(const char *start, size_t len) {
    char *copy = (char*)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, start, len);
    copy[len] = 0;
    return copy;
}

JS_HIDDEN unsigned int fnv1a(const unsigned char *data, int len) {
    unsigned int h = 0x811c9dc5u;
    for (int i = 0; i < len; i++) { h ^= data[i]; h *= 0x01000193u; }
    return h;
}

JS_HIDDEN const char* j2c(JNIEnv *env, jstring js) {
    return js ? (*env)->GetStringUTFChars(env, js, NULL) : NULL;
}

JS_HIDDEN void rls(JNIEnv *env, jstring js, const char *s) {
    if (js && s) (*env)->ReleaseStringUTFChars(env, js, s);
}

JS_HIDDEN int js_pending_exception(JNIEnv *env) {
    return env && (*env)->ExceptionCheck(env);
}

JS_HIDDEN void js_clear_pending_exception(JNIEnv *env) {
    if (js_pending_exception(env)) (*env)->ExceptionClear(env);
}

JS_HIDDEN int starts(const char *s, const char *p) {
    return s && p ? strncmp(s, p, strlen(p)) == 0 : 0;
}

JS_HIDDEN int contains(const char *s, const char *sub) {
    return s && sub ? strstr(s, sub) != NULL : 0;
}

JS_HIDDEN char* js_join_parts(const char *first, ...) {
    va_list ap;
    size_t len = 0;
    const char *part = first;
    va_start(ap, first);
    while (part) {
        len += strlen(part);
        part = va_arg(ap, const char*);
    }
    va_end(ap);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    out[0] = 0;
    part = first;
    va_start(ap, first);
    while (part) {
        strcat(out, part);
        part = va_arg(ap, const char*);
    }
    va_end(ap);
    return out;
}

JS_HIDDEN char* js_helper_owner(const char *a, const char *b, const char *c, const char *d) {
    char *name = js_join_parts(a, b, c, d, NULL);
    if (!name) return NULL;
    char *owner = js_join_parts("io/github/hht0rro/ja", "vash", "roud/trans", "forms/pro", "tection/", name, NULL);
    free(name);
    return owner;
}

JS_HIDDEN char* js_native_name(const char *a, const char *b, const char *c) {
    return js_join_parts("na", "tive", a, b, c, NULL);
}

/*
 * The AKEN page bridge deliberately keeps its purpose-split ABI names visible
 * to the registration manifest.  Return an owned copy so the common
 * registration cleanup can free every method name uniformly.
 */
JS_HIDDEN char* js_native_name_full(const char *name) {
    if (!name) return NULL;
    return js_join_parts(name, NULL);
}

JS_HIDDEN char* js_native_name_obfuscated(const unsigned char *encoded, size_t length, unsigned int mask) {
    if (!encoded || length == 0u || length > 4096u || (mask & ~0xFFu) != 0u) return NULL;
    char *name = (char*)calloc(length + 1u, 1u);
    if (!name) return NULL;
    for (size_t index = 0u; index < length; index++) {
        unsigned char decoded = (unsigned char)(encoded[index] ^ (unsigned char)mask);
        if (decoded == 0u) {
            volatile unsigned char *wipe = (volatile unsigned char*)name;
            for (size_t i = 0u; i <= length; i++) wipe[i] = 0u;
            free(name);
            return NULL;
        }
        name[index] = (char)decoded;
    }
    name[length] = '\0';
    return name;
}
