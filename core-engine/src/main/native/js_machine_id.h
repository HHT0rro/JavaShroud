#ifndef JS_MACHINE_ID_H
#define JS_MACHINE_ID_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Best-effort stable machine fingerprint.
 * Writes a normalized lowercase identifier into |out| (up to |out_len| bytes),
 * returns the number of bytes written (not including NUL), or 0 on failure.
 * The output is NUL-terminated when the buffer has room. */
int js_machine_id(char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
