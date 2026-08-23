#include "native_runtime_benchmark.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int probe_is_zero(const unsigned char *bytes, size_t size) {
    if (!bytes && size != 0u) return 0;
    for (size_t index = 0u; index < size; index++) {
        if (bytes[index] != 0u) return 0;
    }
    return 1;
}

static int probe_decrypt_success(
    bench_state *state,
    const bench_gcm_page *page,
    uint64_t *digest
) {
    int ok;
    if (!state || !page || !digest || !state->scratch || page->plain_size > state->scratch_capacity) return 0;
    memset(state->scratch, 0xa5, page->plain_size);
    ok = js_aes_gcm_decrypt(
        BENCH_GCM_KEY_128,
        sizeof(BENCH_GCM_KEY_128),
        page->nonce,
        page->aad,
        page->aad_size,
        page->ciphertext_and_tag,
        page->ciphertext_and_tag_size,
        state->scratch);
    if (!ok || bench_output_digest(state->scratch, page->plain_size) != page->expected_digest) {
        js_vbc4_wipe_volatile(state->scratch, page->plain_size);
        return 0;
    }
    *digest ^= bench_mix(page->expected_digest ^ (uint64_t)page->plain_size);
    js_vbc4_wipe_volatile(state->scratch, page->plain_size);
    return 1;
}

static int probe_decrypt_reject(
    bench_state *state,
    const bench_gcm_page *page,
    unsigned int tamper_kind,
    uint64_t *digest
) {
    unsigned char *ciphertext = NULL;
    unsigned char *aad = NULL;
    unsigned char nonce[12];
    unsigned char wrong_key[16];
    size_t ciphertext_size;
    size_t checked_plain_size;
    const unsigned char *key = BENCH_GCM_KEY_128;
    size_t key_size = sizeof(BENCH_GCM_KEY_128);
    int ok;
    if (!state || !page || !digest || !state->scratch || !page->ciphertext_and_tag || page->plain_size > state->scratch_capacity) return 0;
    ciphertext_size = page->ciphertext_and_tag_size;
    ciphertext = (unsigned char *)malloc(ciphertext_size);
    aad = (unsigned char *)malloc(page->aad_size == 0u ? 1u : page->aad_size);
    if (!ciphertext || !aad) goto failure;
    memcpy(ciphertext, page->ciphertext_and_tag, ciphertext_size);
    if (page->aad_size != 0u) memcpy(aad, page->aad, page->aad_size);
    memcpy(nonce, page->nonce, sizeof(nonce));
    memset(wrong_key, 0xa5, sizeof(wrong_key));
    switch (tamper_kind) {
        case 0u: /* tag */
            ciphertext[ciphertext_size - 1u] ^= 0x01u;
            break;
        case 1u: /* AAD */
            if (page->aad_size == 0u) goto failure;
            aad[0] ^= 0x01u;
            break;
        case 2u: /* nonce */
            nonce[0] ^= 0x01u;
            break;
        case 3u: /* truncation, retaining at least one tag byte */
            if (ciphertext_size <= 17u) goto failure;
            ciphertext_size -= 1u;
            break;
        case 4u: /* key */
            key = wrong_key;
            break;
        default:
            goto failure;
    }
    /* The decrypt API has no caller-capacity parameter.  On a truncated
     * envelope it can only derive and wipe the number of plaintext bytes
     * represented by the supplied frame (one byte less than the valid page).
     * Check that writable range here, then wipe the complete fixture scratch
     * below so no sentinel or partial plaintext survives the case. */
    checked_plain_size = ciphertext_size >= 16u ? ciphertext_size - 16u : 0u;
    memset(state->scratch, 0xa5, page->plain_size);
    ok = js_aes_gcm_decrypt(
        key,
        key_size,
        nonce,
        page->aad_size == 0u ? NULL : aad,
        page->aad_size,
        ciphertext,
        ciphertext_size,
        state->scratch);
    if (ok || !probe_is_zero(state->scratch, checked_plain_size)) goto failure;
    *digest ^= bench_mix(UINT64_C(0x6a09e667f3bcc909) ^ ((uint64_t)tamper_kind << 32u) ^ (uint64_t)page->plain_size);
    js_vbc4_wipe_volatile(state->scratch, page->plain_size);
    bench_secure_zero(nonce, sizeof(nonce));
    bench_secure_zero(wrong_key, sizeof(wrong_key));
    bench_secure_zero(ciphertext, page->ciphertext_and_tag_size);
    bench_secure_zero(aad, page->aad_size == 0u ? 1u : page->aad_size);
    free(ciphertext);
    free(aad);
    return 1;

failure:
    if (state && state->scratch) js_vbc4_wipe_volatile(state->scratch, page ? page->plain_size : 0u);
    bench_secure_zero(nonce, sizeof(nonce));
    bench_secure_zero(wrong_key, sizeof(wrong_key));
    if (ciphertext) {
        bench_secure_zero(ciphertext, page ? page->ciphertext_and_tag_size : 0u);
        free(ciphertext);
    }
    if (aad) {
        bench_secure_zero(aad, page && page->aad_size != 0u ? page->aad_size : 1u);
        free(aad);
    }
    return 0;
}

static int probe_cross_page_replay_reject(
    bench_state *state,
    const bench_gcm_page *cipher_page,
    const bench_gcm_page *binding_page,
    unsigned int replay_index,
    uint64_t *digest
) {
    int ok;
    if (!state || !cipher_page || !binding_page || !digest || !state->scratch ||
        !cipher_page->ciphertext_and_tag || cipher_page == binding_page ||
        cipher_page->plain_size > state->scratch_capacity) return 0;
    memset(state->scratch, 0xa5, cipher_page->plain_size);
    ok = js_aes_gcm_decrypt(
        BENCH_GCM_KEY_128,
        sizeof(BENCH_GCM_KEY_128),
        binding_page->nonce,
        binding_page->aad,
        binding_page->aad_size,
        cipher_page->ciphertext_and_tag,
        cipher_page->ciphertext_and_tag_size,
        state->scratch);
    if (ok || !probe_is_zero(state->scratch, cipher_page->plain_size)) {
        js_vbc4_wipe_volatile(state->scratch, cipher_page->plain_size);
        return 0;
    }
    *digest ^= bench_mix(
        UINT64_C(0xbb67ae8584caa73b) ^
        ((uint64_t)replay_index << 40u) ^
        ((uint64_t)cipher_page->plain_size << 8u) ^
        (uint64_t)binding_page->plain_size);
    js_vbc4_wipe_volatile(state->scratch, cipher_page->plain_size);
    return 1;
}

/* Exercise the page-bound AES-256 scalar-lane terminal as part of the same
 * hardware/software differential fixture.  The production AKEN bridge passes
 * these lanes independently so the key does not appear as one contiguous
 * byte-array argument.  Keep this vector local to the fixture, verify the
 * plaintext before wiping it, then run one tag rejection to prove the lane
 * path retains the authenticated-open failure wipe contract. */
static int probe_scalar_lane_kat(uint64_t *digest, unsigned int *case_count) {
    static const unsigned char nonce[12] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
        0x06u, 0x07u, 0x08u, 0x09u, 0x0au, 0x0bu
    };
    static const unsigned char aad[7] = {
        0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u
    };
    static const unsigned char ciphertext_and_tag[53] = {
        0x44u, 0x16u, 0xf3u, 0x2du, 0x82u, 0xbdu, 0xabu, 0x61u,
        0x06u, 0xddu, 0x3au, 0x35u, 0x7eu, 0x09u, 0x89u, 0x6fu,
        0x90u, 0xf2u, 0xb2u, 0x72u, 0xa7u, 0x13u, 0x26u, 0xf6u,
        0xa3u, 0xcbu, 0x58u, 0x4bu, 0xc2u, 0x99u, 0x01u, 0xa0u,
        0x22u, 0x24u, 0xebu, 0xaau, 0xc8u, 0xe9u, 0xf9u, 0x9fu,
        0x38u, 0x09u, 0xb5u, 0xaeu, 0x3au, 0x8eu, 0x24u, 0x12u,
        0xedu, 0x70u, 0x2du, 0x5au, 0xb1u
    };
    static const unsigned char expected_plaintext[37] = {
        0x03u, 0x14u, 0x25u, 0x36u, 0x47u, 0x58u, 0x69u, 0x7au,
        0x8bu, 0x9cu, 0xadu, 0xbeu, 0xcfu, 0xe0u, 0xf1u, 0x02u,
        0x13u, 0x24u, 0x35u, 0x46u, 0x57u, 0x68u, 0x79u, 0x8au,
        0x9bu, 0xacu, 0xbdu, 0xceu, 0xdfu, 0xf0u, 0x01u, 0x12u,
        0x23u, 0x34u, 0x45u, 0x56u, 0x67u
    };
    unsigned char output[sizeof(expected_plaintext)];
    unsigned char tampered[sizeof(ciphertext_and_tag)];
    uint32_t lanes[8] = {
        UINT32_C(0x00010203), UINT32_C(0x04050607),
        UINT32_C(0x08090a0b), UINT32_C(0x0c0d0e0f),
        UINT32_C(0x10111213), UINT32_C(0x14151617),
        UINT32_C(0x18191a1b), UINT32_C(0x1c1d1e1f)
    };
    int ok;
    if (!digest || !case_count) return 0;

    memset(output, 0xa5, sizeof(output));
    ok = js_aes_gcm_decrypt_lanes(
        lanes[0], lanes[1], lanes[2], lanes[3], lanes[4], lanes[5], lanes[6], lanes[7],
        nonce, aad, sizeof(aad), ciphertext_and_tag, sizeof(ciphertext_and_tag), output);
    if (!ok || memcmp(output, expected_plaintext, sizeof(output)) != 0) goto failure;
    *digest ^= bench_mix(bench_output_digest(output, sizeof(output)) ^ UINT64_C(0x9e3779b97f4a7c15));
    (*case_count)++;
    js_vbc4_wipe_volatile(output, sizeof(output));

    memcpy(tampered, ciphertext_and_tag, sizeof(tampered));
    tampered[sizeof(tampered) - 1u] ^= 0x01u;
    memset(output, 0xa5, sizeof(output));
    ok = js_aes_gcm_decrypt_lanes(
        lanes[0], lanes[1], lanes[2], lanes[3], lanes[4], lanes[5], lanes[6], lanes[7],
        nonce, aad, sizeof(aad), tampered, sizeof(tampered), output);
    if (ok || !probe_is_zero(output, sizeof(output))) goto failure;
    *digest ^= bench_mix(UINT64_C(0x243f6a8885a308d3) ^ sizeof(tampered));
    (*case_count)++;
    js_vbc4_wipe_volatile(output, sizeof(output));
    bench_secure_zero(tampered, sizeof(tampered));
    bench_secure_zero(lanes, sizeof(lanes));
    return 1;

failure:
    js_vbc4_wipe_volatile(output, sizeof(output));
    bench_secure_zero(tampered, sizeof(tampered));
    bench_secure_zero(lanes, sizeof(lanes));
    return 0;
}

int main(void) {
    bench_state state;
    js_crypto_runtime_metrics metrics;
    uint64_t output_digest = UINT64_C(0x243f6a8885a308d3);
    unsigned int tamper_cases = 0u;
    unsigned int cross_page_replay_cases = 0u;
    unsigned int scalar_lane_cases = 0u;
    unsigned int page_count = 0u;
    memset(&state, 0, sizeof(state));
    memset(&metrics, 0, sizeof(metrics));
    if (!bench_state_init(&state, 1u)) {
        fprintf(stderr, "aken_page_auth_differential failure=fixture-setup\n");
        return 2;
    }
    js_crypto_runtime_metrics_reset();
    for (unsigned int page_index = 0u; page_index < BENCH_PAGE_COUNT; page_index++) {
        const bench_gcm_page *page = &state.pages[page_index];
        if (!probe_decrypt_success(&state, page, &output_digest)) {
            fprintf(stderr, "aken_page_auth_differential failure=valid-page\n");
            bench_state_clear(&state);
            return 3;
        }
        for (unsigned int tamper_kind = 0u; tamper_kind < 5u; tamper_kind++) {
            if (!probe_decrypt_reject(&state, page, tamper_kind, &output_digest)) {
                fprintf(stderr, "aken_page_auth_differential failure=tamper-case\n");
                bench_state_clear(&state);
                return 4;
            }
            ++tamper_cases;
        }
        if (!probe_cross_page_replay_reject(
                &state,
                page,
                &state.pages[(page_index + 1u) % BENCH_PAGE_COUNT],
                page_index,
                &output_digest
            )) {
            fprintf(stderr, "aken_page_auth_differential failure=cross-page-replay\n");
            bench_state_clear(&state);
            return 5;
        }
        ++tamper_cases;
        ++cross_page_replay_cases;
        ++page_count;
    }
    if (!probe_scalar_lane_kat(&output_digest, &scalar_lane_cases)) {
        fprintf(stderr, "aken_page_auth_differential failure=scalar-lane-kat\n");
        bench_state_clear(&state);
        return 7;
    }
    js_crypto_runtime_metrics_snapshot(&metrics);
    if (page_count != BENCH_PAGE_COUNT || tamper_cases != BENCH_PAGE_COUNT * 6u ||
        cross_page_replay_cases != BENCH_PAGE_COUNT ||
        scalar_lane_cases != 2u ||
        metrics.auth_check_count < (uint64_t)(BENCH_PAGE_COUNT * 7u) ||
        metrics.auth_failure_count < (uint64_t)tamper_cases ||
        metrics.tag_check_count < (uint64_t)(BENCH_PAGE_COUNT * 6u) ||
        metrics.length_check_count < (uint64_t)(BENCH_PAGE_COUNT * 7u) ||
        metrics.structure_check_count < (uint64_t)(BENCH_PAGE_COUNT * 7u) ||
        metrics.aes_block_count == 0u || metrics.ghash_block_count == 0u ||
        metrics.wipe_count == 0u || metrics.wipe_failure_count != 0u ||
        metrics.security_checks_skipped != 0u || metrics.fallback_count != 0u ||
        metrics.legacy_path_hits != 0u || metrics.plaintext_persistence_bytes != 0u ||
        metrics.exception_count != 0u) {
        fprintf(stderr, "aken_page_auth_differential failure=security-counters\n");
        bench_state_clear(&state);
        return 6;
    }
    printf(
        "aken_page_auth_differential status=pass page_count=%u tamper_cases=%u cross_page_replay_cases=%u scalar_lane_cases=%u "
        "hardware_aes=%d hardware_ghash=%d hardware_crypto_path=%llu software_crypto_path=%llu "
        "aes_block_count=%llu ghash_block_count=%llu auth_check_count=%llu auth_failure_count=%llu "
        "tag_check_count=%llu length_check_count=%llu structure_check_count=%llu wipe_count=%llu "
        "wipe_failure_count=%llu security_checks_skipped=%llu fallback_count=%llu legacy_path_hits=%llu "
        "plaintext_persistence_bytes=%llu exception_count=%llu output_digest=%016llx\n",
        page_count,
        tamper_cases,
        cross_page_replay_cases,
        scalar_lane_cases,
        js_aes_hardware_available(),
        js_ghash_hardware_available(),
        (unsigned long long)metrics.hardware_crypto_path,
        (unsigned long long)metrics.software_crypto_path,
        (unsigned long long)metrics.aes_block_count,
        (unsigned long long)metrics.ghash_block_count,
        (unsigned long long)metrics.auth_check_count,
        (unsigned long long)metrics.auth_failure_count,
        (unsigned long long)metrics.tag_check_count,
        (unsigned long long)metrics.length_check_count,
        (unsigned long long)metrics.structure_check_count,
        (unsigned long long)metrics.wipe_count,
        (unsigned long long)metrics.wipe_failure_count,
        (unsigned long long)metrics.security_checks_skipped,
        (unsigned long long)metrics.fallback_count,
        (unsigned long long)metrics.legacy_path_hits,
        (unsigned long long)metrics.plaintext_persistence_bytes,
        (unsigned long long)metrics.exception_count,
        (unsigned long long)output_digest);
    bench_state_clear(&state);
    return 0;
}


