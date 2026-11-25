#ifndef QP_R1_FFI_H
#define QP_R1_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define QP_EXPORT __declspec(dllexport)
#else
#define QP_EXPORT __attribute__((visibility("default")))
#endif

#define QP_QP_DIGEST_SIZE 32u
#define QP_R1_MAX_BINDING_SIZE (4u * 1024u)
#define QP_R1_MAX_PAYLOAD_SIZE (16u * 1024u * 1024u)
#define QP_R1_MAX_FRAME_SIZE (4u + 1u + 4u + QP_QP_DIGEST_SIZE + QP_R1_MAX_PAYLOAD_SIZE + QP_QP_DIGEST_SIZE)
#define QP_R1_MAX_TARGET_LENGTH 64u
#define QP_R1_OK 0
#define QP_R1_INVALID_INPUT -1
#define QP_R1_AUTHENTICATION_FAILED -2
#define QP_R1_BUFFER_TOO_SMALL -3
#define QP_R1_UNSUPPORTED_TARGET -4
#define QP_R1_INTERNAL_ERROR -5

#ifdef __cplusplus
extern "C" {
#endif

QP_EXPORT int32_t qp_r1_runtime_binding_digest(
    const uint8_t *binding,
    size_t binding_len,
    uint8_t *digest_out);

QP_EXPORT int32_t qp_r1_open_frame(
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
