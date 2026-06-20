#ifndef JS_PROTECTED_SECTION_H
#define JS_PROTECTED_SECTION_H

#include "js_native_common.h"

#define JS_PROTECTED_SECTION_NAME ".jsx"

#if (defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))) || defined(__linux__) || defined(__ANDROID__)
#define JS_PROTECTED_SECTION_ENABLED 1
#else
#define JS_PROTECTED_SECTION_ENABLED 0
#endif

typedef struct {
    unsigned char magic[8];
    volatile unsigned int state;
    unsigned int section_rva;
    unsigned int section_size;
} js_protected_seal;

JS_HIDDEN const unsigned char* js_protected_section_key(int *len);

#endif
