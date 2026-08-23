#ifndef JSRT_R1_FFI_H
#define JSRT_R1_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define JSRT_EXPORT __declspec(dllexport)
#else
#define JSRT_EXPORT __attribute__((visibility("default")))
#endif

#define JSRT_R1_DIGEST_SIZE 32u
#define JSRT_R1_MAX_BINDING_SIZE (4u * 1024u)
#define JSRT_R1_MAX_PAYLOAD_SIZE (16u * 1024u * 1024u)
#define JSRT_R1_MAX_FRAME_SIZE (4u + 1u + 4u + JSRT_R1_DIGEST_SIZE + JSRT_R1_MAX_PAYLOAD_SIZE + JSRT_R1_DIGEST_SIZE)
#define JSRT_R1_MAX_TARGET_LENGTH 64u
#define JSRT_R1_OK 0
#define JSRT_R1_INVALID_INPUT -1
#define JSRT_R1_AUTHENTICATION_FAILED -2
#define JSRT_R1_BUFFER_TOO_SMALL -3
#define JSRT_R1_UNSUPPORTED_TARGET -4
#define JSRT_R1_INTERNAL_ERROR -5

#ifdef __cplusplus
extern "C" {
#endif

JSRT_EXPORT int32_t jsrt_r1_runtime_binding_digest(
    const uint8_t *binding,
    size_t binding_len,
    uint8_t *digest_out);

JSRT_EXPORT int32_t jsrt_r1_open_frame(
    const uint8_t *target,
    size_t target_len,
    const uint8_t *binding,
    size_t binding_len,
    const uint8_t *frame,
    size_t frame_len,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len_out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
