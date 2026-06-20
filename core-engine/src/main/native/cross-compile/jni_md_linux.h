#ifndef _JAVASOFT_JNI_MD_H_
#define _JAVASOFT_JNI_MD_H_

#include <stdint.h>

#define JNIEXPORT __attribute__((visibility("default")))
#define JNIIMPORT
#define JNICALL

typedef unsigned char jboolean;
typedef signed char jbyte;
typedef unsigned short jchar;
typedef short jshort;
typedef int jint;
#ifdef __LP64__
typedef long jlong;
#else
typedef long long jlong;
#endif
typedef float jfloat;
typedef double jdouble;

typedef jint jsize;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* !_JAVASOFT_JNI_MD_H_ */