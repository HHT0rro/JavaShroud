#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_crypto.h"
#include "js_vm_resource.h"

#define JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN 4096u
#define JS_ZSTD_CONTEXT_PROBE_GROWN_PLAIN_LEN 65536u
#define JS_ZSTD_CONTEXT_PROBE_LARGE_PLAIN_LEN (1024u * 1024u)
#define JS_ZSTD_CONTEXT_PROBE_OVERSIZE_PLAIN_LEN (4u * 1024u * 1024u + 1u)
#define JS_ZSTD_CONTEXT_PROBE_PARTIAL_PLAIN_LEN (128u * 1024u + 4096u)
#define JS_ZSTD_CONTEXT_PROBE_SCRATCH_MAX (4u * 1024u * 1024u)
#define JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY 192u

/* Build a current-format all-zero RLE Zstd frame in the fixture rather than
 * embedding protected artifact bytes.  The probe uses 4 KiB, 64 KiB and a
 * just-over-bound frame to verify both scratch capacity reuse and the bounded
 * direct-output path. */
static size_t js_zstd_context_probe_make_zero_rle_frame(
    unsigned char *out,
    size_t out_capacity,
    uint32_t plain_len
) {
    const uint32_t max_block = 128u * 1024u;
    size_t offset = 0u;
    uint32_t remaining = plain_len;
    if (!out || plain_len < 256u) return 0u;
    if (plain_len <= 0x100ffu) {
        if (out_capacity < 11u) return 0u;
        out[offset++] = 0x28u;
        out[offset++] = 0xb5u;
        out[offset++] = 0x2fu;
        out[offset++] = 0xfdu;
        out[offset++] = 0x60u;
        uint32_t encoded_size = plain_len - 256u;
        out[offset++] = (unsigned char)(encoded_size & 0xffu);
        out[offset++] = (unsigned char)((encoded_size >> 8u) & 0xffu);
    } else {
        if (out_capacity < 13u) return 0u;
        out[offset++] = 0x28u;
        out[offset++] = 0xb5u;
        out[offset++] = 0x2fu;
        out[offset++] = 0xfdu;
        out[offset++] = 0xa0u;
        out[offset++] = (unsigned char)(plain_len & 0xffu);
        out[offset++] = (unsigned char)((plain_len >> 8u) & 0xffu);
        out[offset++] = (unsigned char)((plain_len >> 16u) & 0xffu);
        out[offset++] = (unsigned char)((plain_len >> 24u) & 0xffu);
    }
    while (remaining != 0u) {
        uint32_t block_len = remaining > max_block ? max_block : remaining;
        uint32_t header = (block_len << 3u) | 0x02u | (block_len == remaining ? 0x01u : 0u);
        if (offset + 4u > out_capacity) return 0u;
        out[offset++] = (unsigned char)(header & 0xffu);
        out[offset++] = (unsigned char)((header >> 8u) & 0xffu);
        out[offset++] = (unsigned char)((header >> 16u) & 0xffu);
        out[offset++] = 0u;
        remaining -= block_len;
    }
    return offset;
}

static int js_zstd_context_probe_all_zero(const unsigned char *value, size_t len) {
    if (!value) return 0;
    unsigned char diff = 0u;
    for (size_t index = 0u; index < len; ++index) diff |= value[index];
    return diff == 0u;
}

static void js_zstd_context_probe_release(unsigned char *value, size_t len) {
    if (!value) return;
    js_vbc4_wipe_volatile(value, len);
    free(value);
}

static int js_zstd_context_probe_decode_and_wipe(
    const unsigned char *frame,
    uint32_t frame_len,
    uint32_t plain_len
) {
    unsigned char *plain = js_vbc4_zstd_decompress_owned(
        frame,
        frame_len,
        plain_len
    );
    if (!plain || !js_zstd_context_probe_all_zero(plain, plain_len)) {
        js_zstd_context_probe_release(plain, plain_len);
        return 0;
    }
    js_zstd_context_probe_release(plain, plain_len);
    return 1;
}

int main(void) {
    js_crypto_runtime_metrics metrics_before_reset;
    js_crypto_runtime_metrics metrics_after_reset;
    js_crypto_runtime_metrics metrics_after_failure;
    unsigned int generation_before_reset;
    unsigned int generation_after_reset;
    unsigned char frame[JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY];
    unsigned char grown_frame[JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY];
    unsigned char large_frame[JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY];
    unsigned char oversize_frame[JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY];
    unsigned char partial_malformed[JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY];
    size_t frame_len;
    size_t grown_frame_len;
    size_t large_frame_len;
    size_t oversize_frame_len;
    size_t partial_frame_len;
    size_t initial_workspace_capacity;
    unsigned char malformed[JS_ZSTD_CONTEXT_PROBE_FRAME_CAPACITY];
    unsigned char *plain = NULL;

    frame_len = js_zstd_context_probe_make_zero_rle_frame(
        frame,
        sizeof(frame),
        JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN);
    grown_frame_len = js_zstd_context_probe_make_zero_rle_frame(
        grown_frame,
        sizeof(grown_frame),
        JS_ZSTD_CONTEXT_PROBE_GROWN_PLAIN_LEN);
    large_frame_len = js_zstd_context_probe_make_zero_rle_frame(
        large_frame,
        sizeof(large_frame),
        JS_ZSTD_CONTEXT_PROBE_LARGE_PLAIN_LEN);
    oversize_frame_len = js_zstd_context_probe_make_zero_rle_frame(
        oversize_frame,
        sizeof(oversize_frame),
        JS_ZSTD_CONTEXT_PROBE_OVERSIZE_PLAIN_LEN);
    partial_frame_len = js_zstd_context_probe_make_zero_rle_frame(
        partial_malformed,
        sizeof(partial_malformed),
        JS_ZSTD_CONTEXT_PROBE_PARTIAL_PLAIN_LEN);
    if (frame_len == 0u || grown_frame_len == 0u || large_frame_len == 0u ||
        oversize_frame_len == 0u || partial_frame_len < 2u) {
        fputs("Zstd production context probe: frame setup failed\n", stderr);
        return 1;
    }

    /* Start a fresh current-format resource session.  Resetting the call gate
     * also resets the current thread's owned Zstd context and advances the
     * generation used to reject stale per-thread state. */
    js_vm_call_gate_reset();
    js_crypto_runtime_metrics_reset();

    if (!js_zstd_context_probe_decode_and_wipe(frame, (uint32_t)frame_len, JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN)) {
        fputs("Zstd production context probe: initial decode failed\n", stderr);
        return 1;
    }
    initial_workspace_capacity = js_vm_zstd_scratch_capacity_current_thread();
    if (initial_workspace_capacity == 0u ||
        initial_workspace_capacity > JS_ZSTD_CONTEXT_PROBE_SCRATCH_MAX ||
        !js_zstd_context_probe_decode_and_wipe(frame, (uint32_t)frame_len, JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN) ||
        js_vm_zstd_scratch_capacity_current_thread() != initial_workspace_capacity) {
        fputs("Zstd production context probe: same-generation scratch capacity was not reused\n", stderr);
        return 1;
    }
    if (!js_zstd_context_probe_decode_and_wipe(grown_frame, (uint32_t)grown_frame_len, JS_ZSTD_CONTEXT_PROBE_GROWN_PLAIN_LEN)) {
        fputs("Zstd production context probe: grown scratch decode failed\n", stderr);
        return 1;
    }
    if (js_vm_zstd_scratch_capacity_current_thread() != initial_workspace_capacity ||
        !js_zstd_context_probe_decode_and_wipe(frame, (uint32_t)frame_len, JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN) ||
        js_vm_zstd_scratch_capacity_current_thread() != initial_workspace_capacity) {
        fputs("Zstd production context probe: grown scratch capacity was not retained\n", stderr);
        return 1;
    }
    if (!js_zstd_context_probe_decode_and_wipe(
            large_frame,
            (uint32_t)large_frame_len,
            JS_ZSTD_CONTEXT_PROBE_LARGE_PLAIN_LEN) ||
        js_vm_zstd_scratch_capacity_current_thread() != initial_workspace_capacity) {
        fputs("Zstd production context probe: 1 MiB decode did not reuse bounded workspace\n", stderr);
        return 1;
    }
    if (!js_zstd_context_probe_decode_and_wipe(
            oversize_frame,
            (uint32_t)oversize_frame_len,
            JS_ZSTD_CONTEXT_PROBE_OVERSIZE_PLAIN_LEN) ||
        js_vm_zstd_scratch_capacity_current_thread() != initial_workspace_capacity) {
        fputs("Zstd production context probe: oversize decode retained unbounded scratch\n", stderr);
        return 1;
    }

    js_crypto_runtime_metrics_snapshot(&metrics_before_reset);
    if (metrics_before_reset.decompress_context_reuse_count < 1u ||
        metrics_before_reset.structure_check_count < 6u ||
        metrics_before_reset.length_check_count < 6u ||
        metrics_before_reset.wipe_count < 6u ||
        metrics_before_reset.auth_failure_count != 0u ||
        metrics_before_reset.fallback_count != 0u ||
        metrics_before_reset.legacy_path_hits != 0u ||
        metrics_before_reset.plaintext_persistence_bytes != 0u ||
        metrics_before_reset.security_checks_skipped != 0u) {
        fputs("Zstd production context probe: valid-session metrics failed\n", stderr);
        return 1;
    }

    generation_before_reset = js_vm_resource_session_generation_current();
    js_vm_call_gate_reset();
    generation_after_reset = js_vm_resource_session_generation_current();
    if (generation_after_reset == generation_before_reset ||
        js_vm_zstd_scratch_capacity_current_thread() != 0u ||
        !js_zstd_context_probe_decode_and_wipe(frame, (uint32_t)frame_len, JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN)) {
        fputs("Zstd production context probe: session generation invalidation failed\n", stderr);
        return 1;
    }

    js_crypto_runtime_metrics_snapshot(&metrics_after_reset);
    if (metrics_after_reset.decompress_context_reuse_count != metrics_before_reset.decompress_context_reuse_count ||
        metrics_after_reset.structure_check_count < metrics_before_reset.structure_check_count + 1u ||
        metrics_after_reset.length_check_count < metrics_before_reset.length_check_count + 1u) {
        fputs("Zstd production context probe: stale context was reused across a session reset\n", stderr);
        return 1;
    }

    memcpy(malformed, frame, frame_len);
    malformed[0] ^= 0x01u;
    plain = js_vbc4_zstd_decompress_owned(malformed, (uint32_t)frame_len, JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN);
    js_vbc4_wipe_volatile(malformed, frame_len);
    if (plain) {
        js_zstd_context_probe_release(plain, JS_ZSTD_CONTEXT_PROBE_PLAIN_LEN);
        fputs("Zstd production context probe: malformed frame decoded\n", stderr);
        return 1;
    }

    /* Keep the first RLE block valid and truncate only the second block's
     * payload.  Zstd writes the first block before rejecting the malformed
     * tail; the test-only hook verifies that this partial output is observed
     * and wiped before the owned buffer is released. */
    if (partial_frame_len < 2u) return 1;
    partial_malformed[12u] = 0xa5u;
    js_vm_zstd_test_reset_partial_output_observation();
    plain = js_vbc4_zstd_decompress_owned(
        partial_malformed,
        (uint32_t)(partial_frame_len - 1u),
        JS_ZSTD_CONTEXT_PROBE_PARTIAL_PLAIN_LEN);
    if (plain) {
        js_zstd_context_probe_release(plain, JS_ZSTD_CONTEXT_PROBE_PARTIAL_PLAIN_LEN);
        fputs("Zstd production context probe: partial malformed frame decoded\n", stderr);
        return 1;
    }
    if (js_vm_zstd_test_partial_output_wipe_observed() == 0u) {
        fputs("Zstd production context probe: partial output wipe was not observed\n", stderr);
        return 1;
    }

    js_crypto_runtime_metrics_snapshot(&metrics_after_failure);
    if (metrics_after_failure.structure_check_count < metrics_after_reset.structure_check_count + 1u ||
        metrics_after_failure.length_check_count < metrics_after_reset.length_check_count + 1u ||
        metrics_after_failure.wipe_count <= metrics_after_reset.wipe_count ||
        metrics_after_failure.auth_failure_count != 0u ||
        metrics_after_failure.fallback_count != 0u ||
        metrics_after_failure.legacy_path_hits != 0u ||
        metrics_after_failure.plaintext_persistence_bytes != 0u ||
        metrics_after_failure.security_checks_skipped != 0u) {
        fputs("Zstd production context probe: malformed-frame cleanup metrics failed\n", stderr);
        return 1;
    }

    printf(
        "Zstd production context probe: PASS generation_before=%u generation_after=%u reuse=%llu wipes=%llu workspace_capacity=%llu partial_output_wipe=1\n",
        generation_before_reset,
        generation_after_reset,
        (unsigned long long)metrics_after_failure.decompress_context_reuse_count,
        (unsigned long long)metrics_after_failure.wipe_count,
        (unsigned long long)initial_workspace_capacity
    );
    return 0;
}
