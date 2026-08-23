/*
 * JavaShroud native-runtime benchmark fixture.
 *
 * The fixture deliberately exercises only public native-runtime entry points.
 * It records timings and de-identified counters/digests; it never writes a
 * test key, nonce, plaintext, descriptor material, or filesystem path to its
 * report.  Synthetic page plaintext is held only in a wipe-on-use scratch
 * buffer.  The stored page and shell fixtures retain authenticated ciphertext,
 * tags, and the public synthetic API metadata needed to invoke the test path;
 * they never retain a page plaintext or emit any fixture input.
 *
 * Build a standalone runner by linking this source with js_crypto.c and
 * js_shell_crypto.c and defining JS_RUNTIME_BENCH_MAIN.  The default command
 * runs the 100-sample profile.  Pass --matrix to execute 100, 1000, 10000,
 * and 100000 samples; the latter intentionally includes 1 MiB operations and
 * can take a substantial amount of time.
 */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "js_crypto.h"
#include "js_shell_crypto.h"

/*
 * The default runner intentionally has no attached JVM or artifact session.
 * A full native integration build may opt into the production resource-index
 * adapter below.  It links the same js_vm_resource.c implementation used by
 * the runtime and exercises its immutable alias/commitment index plus the
 * production JSRP commitment verifier.  The adapter is kept compile-time
 * optional so the small crypto/shell smoke runner remains unchanged.
 */
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
#include "js_vm_core.h"
#include "js_vm_resource.h"
#endif

/*
 * The benchmark is normally linked against only the crypto/shell fixture
 * objects.  A full native build may additionally define JS_RUNTIME_BENCH_ZSTD
 * and provide the repository's zstd decoder sources; the conditional include
 * keeps the default standalone smoke build independent of that optional
 * integration dependency.
 */
#if defined(JS_RUNTIME_BENCH_ZSTD)
#include "zstd/zstd.h"
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static uint64_t bench_ticks(void) {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return (uint64_t)value.QuadPart;
}
static uint64_t bench_elapsed_ns(uint64_t elapsed) {
    static LARGE_INTEGER frequency;
    uint64_t frequency_value;
    if (frequency.QuadPart == 0) QueryPerformanceFrequency(&frequency);
    frequency_value = frequency.QuadPart > 0 ? (uint64_t)frequency.QuadPart : 0u;
    if (frequency_value == 0u) return 0u;
    return (elapsed / frequency_value) * UINT64_C(1000000000) +
        ((elapsed % frequency_value) * UINT64_C(1000000000)) / frequency_value;
}
#else
#include <time.h>
static uint64_t bench_ticks(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static uint64_t bench_elapsed_ns(uint64_t elapsed) { return elapsed; }
#endif

enum {
    BENCH_MAX_SAMPLES = 100000u,
    BENCH_DEFAULT_SAMPLES = 100u,
    BENCH_DEFAULT_WARMUP = 16u,
    BENCH_MAX_WARMUP = 100000u,
    BENCH_PAGE_4K = 4u * 1024u,
    BENCH_PAGE_64K = 64u * 1024u,
    BENCH_PAGE_1M = 1024u * 1024u,
    BENCH_PAGE_COUNT = 3u,
    BENCH_SHELL_CHUNK_SIZE = 4u * 1024u,
    BENCH_MAX_PHASES = 32u,
    BENCH_PAGE_AAD_SIZE = 48u
};

enum {
    BENCH_RESOURCE_INDEX_CAPACITY = 16u,
    BENCH_RESOURCE_INDEX_COUNT = 8u,
    BENCH_ZSTD_PLAIN_SIZE = 4096u
};

enum {
    BENCH_BASELINE_AUTH = 1u << 0,
    BENCH_BASELINE_DIGEST = 1u << 1,
    BENCH_BASELINE_TAG = 1u << 2,
    BENCH_BASELINE_LENGTH = 1u << 3,
    BENCH_BASELINE_STRUCTURE = 1u << 4,
    BENCH_BASELINE_JNI_ABI = 1u << 5,
    BENCH_BASELINE_WIPE = 1u << 6,
    BENCH_BASELINE_REQUIRED_MASK =
        BENCH_BASELINE_AUTH |
        BENCH_BASELINE_DIGEST |
        BENCH_BASELINE_TAG |
        BENCH_BASELINE_LENGTH |
        BENCH_BASELINE_STRUCTURE |
        BENCH_BASELINE_JNI_ABI |
        BENCH_BASELINE_WIPE
};

static const unsigned int BENCH_STANDARD_SAMPLE_COUNTS[] = {100u, 1000u, 10000u, 100000u};
static const size_t BENCH_PAGE_SIZES[BENCH_PAGE_COUNT] = {
    BENCH_PAGE_4K,
    BENCH_PAGE_64K,
    BENCH_PAGE_1M
};

/* Public NIST AES-GCM known-answer vectors; they are fixture inputs, never report data. */
static const unsigned char BENCH_GCM_KEY_128[16] = {0};
static const unsigned char BENCH_GCM_KEY_256[32] = {0};
static const unsigned char BENCH_GCM_NONCE_ZERO[12] = {0};
static const unsigned char BENCH_GCM_128_CIPHERTEXT_AND_TAG[32] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
    0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};
static const unsigned char BENCH_GCM_256_CIPHERTEXT_AND_TAG[32] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
};
static const unsigned char BENCH_CTR_KEY_128[16] = {
    0x1f, 0x87, 0x55, 0xb9, 0x24, 0x6d, 0xe0, 0x4a,
    0xd6, 0x03, 0xc8, 0x71, 0x2e, 0x95, 0x6f, 0x3b
};
static const unsigned char BENCH_CTR_KEY_256[32] = {
    0x8a, 0x09, 0x6e, 0x72, 0x31, 0xe5, 0x4c, 0x0d,
    0xbc, 0x41, 0x5f, 0x88, 0x21, 0xb6, 0x7a, 0x90,
    0x17, 0xfa, 0x36, 0x59, 0xc4, 0x28, 0xed, 0x53,
    0x6b, 0x02, 0x9e, 0xf1, 0x74, 0xad, 0x62, 0x0c
};
static const unsigned char BENCH_CTR_IV[16] = {
    0x4a, 0x53, 0x52, 0x54, 0x2d, 0x43, 0x54, 0x52,
    0x2d, 0x42, 0x45, 0x4e, 0x43, 0x48, 0x2d, 0x31
};
static const unsigned char BENCH_SHELL_STREAM_KEY[32] = {
    0x82, 0x3b, 0x6d, 0x54, 0x29, 0xf1, 0x0a, 0x73,
    0xc5, 0x11, 0x94, 0x2e, 0x6f, 0xda, 0x30, 0xb8,
    0x77, 0x09, 0xe3, 0x4c, 0x95, 0x21, 0xab, 0x60,
    0x1d, 0xfe, 0x48, 0x86, 0x3a, 0xb7, 0x5c, 0xd0
};
static const unsigned char BENCH_SHELL_NONCE[16] = {
    0x9c, 0x45, 0xea, 0x16, 0x3f, 0x81, 0xd7, 0x2b,
    0x50, 0xa4, 0x38, 0xfe, 0x69, 0x0d, 0xc1, 0x75
};
static const unsigned char BENCH_SHELL_BINDING_TAG[32] = {
    0x42, 0x11, 0xdb, 0x73, 0x28, 0x9a, 0x04, 0xe6,
    0xbc, 0x5f, 0xd8, 0x30, 0x16, 0xa7, 0x64, 0x2d,
    0xf0, 0x58, 0x9e, 0x37, 0xc3, 0x6a, 0x85, 0x19,
    0xae, 0x4b, 0x70, 0x0c, 0xd5, 0x2e, 0xf6, 0x93
};

typedef struct {
    uint64_t *samples;
    size_t capacity;
    size_t count;
    uint64_t digest;
} bench_series;

typedef struct {
    uint64_t p50;
    uint64_t p95;
    uint64_t p99;
    uint64_t max;
} bench_latency;

typedef struct {
    uint64_t allocation_count;
    uint64_t allocation_bytes;
    uint64_t free_count;
    uint64_t exception_count;
} bench_fixture_counters;

typedef struct {
    unsigned char *ciphertext_and_tag;
    size_t plain_size;
    size_t ciphertext_and_tag_size;
    unsigned char nonce[12];
    unsigned char aad[BENCH_PAGE_AAD_SIZE];
    size_t aad_size;
    uint64_t expected_digest;
} bench_gcm_page;

typedef struct {
    unsigned char *encoded;
    unsigned char *chunk_tags;
    size_t size;
    size_t chunk_tags_size;
    unsigned int chunk_size;
    uint64_t expected_digest;
} bench_shell_payload;

typedef struct {
    bench_fixture_counters fixture;
    uint64_t *timing_samples;
    size_t timing_capacity;
    unsigned char *scratch;
    size_t scratch_capacity;
    bench_gcm_page pages[BENCH_PAGE_COUNT];
    bench_shell_payload shell_payloads[BENCH_PAGE_COUNT];
} bench_state;

typedef struct {
    js_crypto_runtime_metrics metrics;
    bench_fixture_counters fixture;
    bench_latency phase_latency[BENCH_MAX_PHASES];
    size_t phase_count;
    size_t synthetic_phase_count;
    size_t unsupported_phase_count;
    /* Every phase named by this standalone fixture is required production
     * coverage in the runtime plan. A synthetic or unsupported adapter can
     * report useful local timing, but cannot close that production gate. */
    size_t required_production_nonproduction_phase_count;
    uint64_t output_digest;
} bench_summary;

typedef struct {
    js_crypto_runtime_metrics minimum;
    uint64_t differential_output_digest;
    unsigned int field_mask;
    unsigned int supplied;
    unsigned int valid;
    unsigned int has_differential_output_digest;
} bench_security_baseline;

typedef enum {
    BENCH_RESULT_PASS = 0,
    BENCH_RESULT_COVERAGE_INCOMPLETE = 1,
    BENCH_RESULT_SECURITY_BLOCKED = 2
} bench_result_status;

/* Fixture-only immutable lookup table.  It contains hashes and numeric
 * identities only; no resource path, plaintext, key, nonce, or DEK is stored.
 * This deliberately mirrors the shape of the production index without
 * pretending to be an AKEN catalog integration test.
 */
typedef struct {
    uint64_t hash;
    uint32_t identity;
    unsigned char occupied;
} bench_resource_index_entry;

typedef struct {
    bench_resource_index_entry entries[BENCH_RESOURCE_INDEX_CAPACITY];
    size_t count;
    uint32_t generation;
} bench_resource_index;

typedef struct {
    uint64_t loader_identity;
    uint64_t class_identity;
    uint64_t method_identity;
    uint32_t abi_generation;
    uint32_t session_generation;
    unsigned char valid;
} bench_jni_cache_fixture;

#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
typedef struct {
    unsigned char raw[256];
    size_t raw_len;
    char manifest[512];
    char path[JS_VM_CALL_GATE_KEY_LEN];
    char alias[JS_VM_CALL_GATE_KEY_LEN];
    uint32_t partition_id;
} bench_production_resource_fixture;
#endif

static uint64_t bench_mix(uint64_t value) {
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static void bench_secure_zero(void *bytes, size_t size) {
    volatile unsigned char *cursor = (volatile unsigned char *)bytes;
    while (cursor && size--) *cursor++ = 0;
}

static char *bench_trim_ascii(char *text) {
    char *end;
    if (!text) return NULL;
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') ++text;
    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static int bench_parse_counter_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long parsed;
    if (!text || !out || *text == '\0') return 0;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0' || (unsigned long long)(uint64_t)parsed != parsed) return 0;
    *out = (uint64_t)parsed;
    return 1;
}

static int bench_parse_digest_u64(const char *text, uint64_t *out) {
    uint64_t value = 0u;
    if (!text || !out || strlen(text) != 16u) return 0;
    for (size_t index = 0u; index < 16u; index++) {
        unsigned char c = (unsigned char)text[index];
        unsigned int nibble;
        if (c >= '0' && c <= '9') nibble = (unsigned int)(c - '0');
        else if (c >= 'a' && c <= 'f') nibble = (unsigned int)(c - 'a') + 10u;
        else if (c >= 'A' && c <= 'F') nibble = (unsigned int)(c - 'A') + 10u;
        else return 0;
        value = (value << 4u) | (uint64_t)nibble;
    }
    *out = value;
    return 1;
}

static int bench_security_baseline_set_counter(
    bench_security_baseline *baseline,
    const char *name,
    uint64_t value
) {
    uint64_t *slot = NULL;
    unsigned int bit = 0u;
    if (!baseline || !name) return 0;
    if (strcmp(name, "auth_check_count") == 0) {
        slot = &baseline->minimum.auth_check_count;
        bit = BENCH_BASELINE_AUTH;
    } else if (strcmp(name, "digest_check_count") == 0) {
        slot = &baseline->minimum.digest_check_count;
        bit = BENCH_BASELINE_DIGEST;
    } else if (strcmp(name, "tag_check_count") == 0) {
        slot = &baseline->minimum.tag_check_count;
        bit = BENCH_BASELINE_TAG;
    } else if (strcmp(name, "length_check_count") == 0) {
        slot = &baseline->minimum.length_check_count;
        bit = BENCH_BASELINE_LENGTH;
    } else if (strcmp(name, "structure_check_count") == 0) {
        slot = &baseline->minimum.structure_check_count;
        bit = BENCH_BASELINE_STRUCTURE;
    } else if (strcmp(name, "jni_abi_check_count") == 0) {
        slot = &baseline->minimum.jni_abi_check_count;
        bit = BENCH_BASELINE_JNI_ABI;
    } else if (strcmp(name, "wipe_count") == 0) {
        slot = &baseline->minimum.wipe_count;
        bit = BENCH_BASELINE_WIPE;
    } else {
        return 0;
    }
    if ((baseline->field_mask & bit) != 0u) return 0;
    *slot = value;
    baseline->field_mask |= bit;
    return 1;
}

/* Baselines are deliberately text-only counter/digest records. The strict
 * parser rejects duplicate, missing, malformed, or unknown fields so a typo
 * cannot silently weaken the security floor. */
static int bench_security_baseline_load(const char *path, bench_security_baseline *baseline) {
    FILE *input;
    char line[256];
    if (!path || !baseline) return 0;
    memset(baseline, 0, sizeof(*baseline));
    baseline->supplied = 1u;
    input = fopen(path, "rb");
    if (!input) return 0;
    while (fgets(line, sizeof(line), input) != NULL) {
        char *text;
        char *separator;
        char *name;
        char *value;
        uint64_t parsed;
        size_t line_size = strlen(line);
        if (line_size == sizeof(line) - 1u && line[line_size - 1u] != '\n' && !feof(input)) goto invalid;
        text = bench_trim_ascii(line);
        if (!text || *text == '\0' || *text == '#') continue;
        separator = strchr(text, '=');
        if (!separator || strchr(separator + 1, '=') != NULL) goto invalid;
        *separator = '\0';
        name = bench_trim_ascii(text);
        value = bench_trim_ascii(separator + 1);
        if (!name || !value || *name == '\0' || *value == '\0') goto invalid;
        if (strcmp(name, "differential_output_digest") == 0) {
            if (baseline->has_differential_output_digest || !bench_parse_digest_u64(value, &parsed)) goto invalid;
            baseline->differential_output_digest = parsed;
            baseline->has_differential_output_digest = 1u;
        } else {
            if (!bench_parse_counter_u64(value, &parsed) || !bench_security_baseline_set_counter(baseline, name, parsed)) goto invalid;
        }
    }
    if (ferror(input) || baseline->field_mask != BENCH_BASELINE_REQUIRED_MASK) goto invalid;
    if (fclose(input) != 0) {
        memset(&baseline->minimum, 0, sizeof(baseline->minimum));
        baseline->valid = 0u;
        return 0;
    }
    baseline->valid = 1u;
    return 1;

invalid:
    (void)fclose(input);
    memset(&baseline->minimum, 0, sizeof(baseline->minimum));
    baseline->field_mask = 0u;
    baseline->valid = 0u;
    baseline->has_differential_output_digest = 0u;
    baseline->differential_output_digest = 0u;
    return 0;
}

static void bench_security_baseline_from_metrics(
    bench_security_baseline *baseline,
    const js_crypto_runtime_metrics *minimum,
    int has_differential_output_digest,
    uint64_t differential_output_digest
) {
    if (!baseline) return;
    memset(baseline, 0, sizeof(*baseline));
    if (!minimum) return;
    baseline->minimum = *minimum;
    baseline->field_mask = BENCH_BASELINE_REQUIRED_MASK;
    baseline->supplied = 1u;
    baseline->valid = 1u;
    baseline->has_differential_output_digest = has_differential_output_digest ? 1u : 0u;
    baseline->differential_output_digest = differential_output_digest;
}

static const char *bench_baseline_status(const bench_security_baseline *baseline) {
    if (!baseline || !baseline->supplied) return "missing";
    return baseline->valid ? "valid" : "invalid";
}

static int bench_baseline_floor_met(
    const js_crypto_runtime_metrics *actual,
    const bench_security_baseline *baseline
) {
    const js_crypto_runtime_metrics *minimum;
    if (!actual || !baseline || !baseline->valid || baseline->field_mask != BENCH_BASELINE_REQUIRED_MASK) return 0;
    minimum = &baseline->minimum;
    return actual->auth_check_count >= minimum->auth_check_count &&
        actual->digest_check_count >= minimum->digest_check_count &&
        actual->tag_check_count >= minimum->tag_check_count &&
        actual->length_check_count >= minimum->length_check_count &&
        actual->structure_check_count >= minimum->structure_check_count &&
        actual->jni_abi_check_count >= minimum->jni_abi_check_count &&
        actual->wipe_count >= minimum->wipe_count;
}

static uint64_t bench_text_digest(const char *text) {
    uint64_t digest = UINT64_C(0x6a09e667f3bcc909);
    if (!text) return digest;
    while (*text) digest = bench_mix(digest ^ (unsigned char)*text++);
    return digest;
}

static uint64_t bench_output_digest(const unsigned char *bytes, size_t size) {
    uint64_t digest = bench_mix(UINT64_C(0x243f6a8885a308d3) ^ (uint64_t)size);
    size_t stride;
    if (!bytes && size != 0u) return bench_mix(digest ^ UINT64_C(0xffffffffffffffff));
    if (size == 0u) return digest;
    stride = size <= 128u ? 1u : size / 128u;
    for (size_t index = 0u; index < size; index += stride) {
        digest = bench_mix(digest ^ ((uint64_t)bytes[index] | ((uint64_t)index << 8)));
    }
    return bench_mix(digest ^ ((uint64_t)bytes[size - 1u] << 56));
}

#if !defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
static size_t bench_index_slot(uint64_t hash) {
    return (size_t)(bench_mix(hash) % BENCH_RESOURCE_INDEX_CAPACITY);
}

static int bench_resource_index_insert(bench_resource_index *index, uint64_t hash, uint32_t identity) {
    size_t slot;
    if (!index || hash == 0u || index->count >= BENCH_RESOURCE_INDEX_CAPACITY) return 0;
    slot = bench_index_slot(hash);
    for (size_t probe = 0u; probe < BENCH_RESOURCE_INDEX_CAPACITY; probe++) {
        bench_resource_index_entry *entry = &index->entries[(slot + probe) % BENCH_RESOURCE_INDEX_CAPACITY];
        if (!entry->occupied) {
            entry->hash = hash;
            entry->identity = identity;
            entry->occupied = 1u;
            ++index->count;
            return 1;
        }
        /* Duplicate aliases/commitments are fail-closed, just as the
         * production immutable index does. */
        if (entry->hash == hash) return 0;
    }
    return 0;
}

static int bench_resource_index_lookup(const bench_resource_index *index, uint64_t hash, uint32_t *identity) {
    size_t slot;
    if (!index || !identity || hash == 0u) return 0;
    slot = bench_index_slot(hash);
    for (size_t probe = 0u; probe < BENCH_RESOURCE_INDEX_CAPACITY; probe++) {
        const bench_resource_index_entry *entry = &index->entries[(slot + probe) % BENCH_RESOURCE_INDEX_CAPACITY];
        if (!entry->occupied) return 0;
        if (entry->hash == hash) {
            *identity = entry->identity;
            return 1;
        }
    }
    return 0;
}

static int bench_resource_index_prepare(bench_resource_index *index, uint64_t domain) {
    if (!index) return 0;
    memset(index, 0, sizeof(*index));
    index->generation = 1u;
    for (unsigned int item = 0u; item < BENCH_RESOURCE_INDEX_COUNT; item++) {
        uint64_t hash = bench_mix(domain ^ ((uint64_t)item + UINT64_C(0x1001)));
        if (!bench_resource_index_insert(index, hash, item + 1u)) {
            bench_secure_zero(index, sizeof(*index));
            return 0;
        }
    }
    return 1;
}
#endif

static int bench_jni_cache_fixture_prepare(bench_jni_cache_fixture *cache) {
    if (!cache) return 0;
    memset(cache, 0, sizeof(*cache));
    cache->loader_identity = bench_mix(UINT64_C(0x6c6f61646572));
    cache->class_identity = bench_mix(UINT64_C(0x636c617373));
    cache->method_identity = bench_mix(UINT64_C(0x6d6574686f64));
    cache->abi_generation = 1u;
    cache->session_generation = 1u;
    cache->valid = 1u;
    return 1;
}

#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
static void bench_production_resource_hex32(const unsigned char value[32], char out[65]) {
    static const char digits[] = "0123456789abcdef";
    if (!value || !out) return;
    for (size_t index = 0u; index < 32u; index++) {
        out[index * 2u] = digits[(value[index] >> 4u) & 0x0Fu];
        out[index * 2u + 1u] = digits[value[index] & 0x0Fu];
    }
    out[64] = '\0';
}

/*
 * Build one bounded, current-format JSRP commitment entry and install it
 * through the production immutable resource index.  The bytes are only a
 * verifier fixture: no decoded resource, key, nonce, or plaintext is kept.
 */
static int bench_production_resource_fixture_prepare(bench_production_resource_fixture *fixture) {
    unsigned char digest[32];
    char digest_text[65];
    int manifest_len;
    if (!fixture) return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->raw_len = 64u;
    fixture->partition_id = 0u;
    (void)snprintf(fixture->path, sizeof(fixture->path), "META-INF/.bench/resource.jsrp");
    (void)snprintf(fixture->alias, sizeof(fixture->alias), "META-INF/.bench/resource.alias");
    for (size_t index = 0u; index < fixture->raw_len; index++) {
        fixture->raw[index] = (unsigned char)bench_mix(UINT64_C(0x736a72702d62656e) ^ index);
    }
    fixture->raw[0] = 'J';
    fixture->raw[1] = 'S';
    fixture->raw[2] = 'R';
    fixture->raw[3] = 'P';
    fixture->raw[4] = 8u;
    fixture->raw[25] = (unsigned char)fixture->partition_id;
    fixture->raw[26] = (unsigned char)(fixture->partition_id >> 8u);
    js_runtime_sha256(fixture->raw, (int)fixture->raw_len, digest);
    bench_production_resource_hex32(digest, digest_text);
    manifest_len = snprintf(
        fixture->manifest,
        sizeof(fixture->manifest),
        "R|%s|%zu|%s|%u\n",
        fixture->path,
        fixture->raw_len,
        digest_text,
        fixture->partition_id);
    bench_secure_zero(digest, sizeof(digest));
    bench_secure_zero(digest_text, sizeof(digest_text));
    if (manifest_len <= 0 || (size_t)manifest_len >= sizeof(fixture->manifest)) {
        bench_secure_zero(fixture, sizeof(*fixture));
        return 0;
    }
    js_vm_call_gate_reset();
    if (!js_vm_commitments_install((const unsigned char *)fixture->manifest, manifest_len) ||
        !js_vm_resource_alias_register(fixture->alias, fixture->path)) {
        js_vm_call_gate_reset();
        bench_secure_zero(fixture, sizeof(*fixture));
        return 0;
    }
    return 1;
}
#endif

static void bench_fill(unsigned char *bytes, size_t size, uint64_t seed) {
    uint64_t state = bench_mix(seed ^ (uint64_t)size);
    if (!bytes && size != 0u) return;
    for (size_t index = 0u; index < size; index++) {
        if ((index & 7u) == 0u) state = bench_mix(state ^ (uint64_t)index);
        bytes[index] = (unsigned char)(state >> ((index & 7u) * 8u));
    }
}

static int bench_compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

static size_t bench_percentile_index(size_t count, unsigned int permille) {
    size_t rank;
    if (count == 0u || permille == 0u) return 0u;
    if (count > SIZE_MAX / permille) return count - 1u;
    rank = (count * (size_t)permille + 999u) / 1000u;
    if (rank == 0u) rank = 1u;
    if (rank > count) rank = count;
    return rank - 1u;
}

static void bench_series_begin(bench_series *series, uint64_t *samples, size_t capacity, const char *phase_name) {
    if (!series) return;
    series->samples = samples;
    series->capacity = capacity;
    series->count = 0u;
    series->digest = bench_mix(bench_text_digest(phase_name));
}

static int bench_series_record(bench_series *series, uint64_t elapsed_ns, uint64_t output) {
    if (!series || !series->samples || series->count >= series->capacity) return 0;
    series->samples[series->count++] = elapsed_ns;
    /* Output-only digest: timing values must not perturb reproducibility. */
    series->digest = bench_mix(series->digest ^ output);
    return 1;
}

static bench_latency bench_series_finish(bench_series *series) {
    bench_latency latency = {0};
    if (!series || !series->samples || series->count == 0u) return latency;
    qsort(series->samples, series->count, sizeof(series->samples[0]), bench_compare_u64);
    latency.p50 = series->samples[bench_percentile_index(series->count, 500u)];
    latency.p95 = series->samples[bench_percentile_index(series->count, 950u)];
    latency.p99 = series->samples[bench_percentile_index(series->count, 990u)];
    latency.max = series->samples[series->count - 1u];
    return latency;
}

static void *bench_alloc(bench_fixture_counters *counters, size_t size) {
    void *value;
    if (!counters || size == 0u) {
        if (counters) ++counters->exception_count;
        return NULL;
    }
    value = malloc(size);
    if (!value) {
        ++counters->exception_count;
        return NULL;
    }
    ++counters->allocation_count;
    counters->allocation_bytes += (uint64_t)size;
    return value;
}

static void bench_wipe_free(bench_fixture_counters *counters, void *bytes, size_t size) {
    if (!bytes) return;
    bench_secure_zero(bytes, size);
    free(bytes);
    if (counters) ++counters->free_count;
}

static void bench_fixture_delta(
    bench_fixture_counters *out,
    const bench_fixture_counters *before,
    const bench_fixture_counters *after
) {
    if (!out || !before || !after) return;
    out->allocation_count = after->allocation_count - before->allocation_count;
    out->allocation_bytes = after->allocation_bytes - before->allocation_bytes;
    out->free_count = after->free_count - before->free_count;
    out->exception_count = after->exception_count - before->exception_count;
}

static void bench_metrics_add(js_crypto_runtime_metrics *out, const js_crypto_runtime_metrics *value) {
    uint64_t *dst = (uint64_t *)out;
    const uint64_t *src = (const uint64_t *)value;
    _Static_assert(sizeof(js_crypto_runtime_metrics) % sizeof(uint64_t) == 0u, "metric ABI must remain counter-only");
    if (!out || !value) return;
    for (size_t index = 0u; index < sizeof(*out) / sizeof(uint64_t); index++) dst[index] += src[index];
}

static void bench_metrics_delta(
    js_crypto_runtime_metrics *out,
    const js_crypto_runtime_metrics *before,
    const js_crypto_runtime_metrics *after
) {
    uint64_t *dst = (uint64_t *)out;
    const uint64_t *left = (const uint64_t *)before;
    const uint64_t *right = (const uint64_t *)after;
    _Static_assert(sizeof(js_crypto_runtime_metrics) % sizeof(uint64_t) == 0u, "metric ABI must remain counter-only");
    if (!out || !before || !after) return;
    for (size_t index = 0u; index < sizeof(*out) / sizeof(uint64_t); index++) {
        dst[index] = right[index] >= left[index] ? right[index] - left[index] : 0u;
    }
}

static void bench_gcm_inc32(unsigned char counter[16]) {
    for (int index = 15; index >= 12; index--) {
        counter[index] = (unsigned char)(counter[index] + 1u);
        if (counter[index] != 0u) break;
    }
}

/* Reference GHASH exists only to prepare public AES-128 fixture ciphertext
 * outside measured phases.  The measured page-open path always invokes the
 * runtime's js_aes_gcm_decrypt, including its production GHASH implementation. */
static void bench_ghash_multiply(unsigned char value[16], const unsigned char hash_subkey[16]) {
    unsigned char product[16] = {0};
    unsigned char factor[16];
    memcpy(factor, hash_subkey, sizeof(factor));
    for (unsigned int bit_index = 0u; bit_index < 128u; bit_index++) {
        unsigned int bit = (unsigned int)((value[bit_index / 8u] >> (7u - (bit_index & 7u))) & 1u);
        unsigned int lsb;
        if (bit) {
            for (unsigned int index = 0u; index < 16u; index++) product[index] ^= factor[index];
        }
        lsb = factor[15] & 1u;
        for (int index = 15; index > 0; index--) {
            factor[index] = (unsigned char)((factor[index] >> 1u) | ((factor[index - 1] & 1u) << 7u));
        }
        factor[0] >>= 1u;
        if (lsb) factor[0] ^= 0xe1u;
    }
    memcpy(value, product, sizeof(product));
    bench_secure_zero(product, sizeof(product));
    bench_secure_zero(factor, sizeof(factor));
}

static void bench_ghash_block(unsigned char state[16], const unsigned char hash_subkey[16], const unsigned char block[16]) {
    for (unsigned int index = 0u; index < 16u; index++) state[index] ^= block[index];
    bench_ghash_multiply(state, hash_subkey);
}

static void bench_ghash_update(
    unsigned char state[16],
    const unsigned char hash_subkey[16],
    const unsigned char *bytes,
    size_t size
) {
    unsigned char block[16] = {0};
    if (!bytes && size != 0u) return;
    while (size >= 16u) {
        bench_ghash_block(state, hash_subkey, bytes);
        bytes += 16u;
        size -= 16u;
    }
    if (size != 0u) {
        memcpy(block, bytes, size);
        bench_ghash_block(state, hash_subkey, block);
    }
    bench_secure_zero(block, sizeof(block));
}

static void bench_store_be64(unsigned char out[8], uint64_t value) {
    for (unsigned int index = 0u; index < 8u; index++) {
        out[7u - index] = (unsigned char)(value >> (index * 8u));
    }
}

static int bench_gcm128_encrypt(
    const unsigned char key[16],
    const unsigned char nonce[12],
    const unsigned char *aad,
    size_t aad_size,
    const unsigned char *plain,
    size_t plain_size,
    unsigned char *ciphertext_and_tag
) {
    unsigned char zero[16] = {0};
    unsigned char hash_subkey[16] = {0};
    unsigned char ghash[16] = {0};
    unsigned char j0[16] = {0};
    unsigned char counter[16] = {0};
    unsigned char stream[16] = {0};
    unsigned char tag_mask[16] = {0};
    unsigned char lengths[16] = {0};
    int ok = 0;
    if (!key || !nonce || (!aad && aad_size != 0u) || (!plain && plain_size != 0u) || !ciphertext_and_tag) goto cleanup;
    if (aad_size > (size_t)(UINT64_MAX / 8u) || plain_size > (size_t)(UINT64_MAX / 8u)) goto cleanup;
    memcpy(j0, nonce, 12u);
    j0[15] = 1u;
    js_aes128_encrypt_block(zero, key, hash_subkey);
    memcpy(counter, j0, sizeof(counter));
    for (size_t offset = 0u; offset < plain_size; offset += 16u) {
        size_t take = plain_size - offset < 16u ? plain_size - offset : 16u;
        bench_gcm_inc32(counter);
        js_aes128_encrypt_block(counter, key, stream);
        for (size_t index = 0u; index < take; index++) ciphertext_and_tag[offset + index] = (unsigned char)(plain[offset + index] ^ stream[index]);
    }
    bench_ghash_update(ghash, hash_subkey, aad, aad_size);
    bench_ghash_update(ghash, hash_subkey, ciphertext_and_tag, plain_size);
    bench_store_be64(lengths, (uint64_t)aad_size * 8u);
    bench_store_be64(lengths + 8u, (uint64_t)plain_size * 8u);
    bench_ghash_block(ghash, hash_subkey, lengths);
    js_aes128_encrypt_block(j0, key, tag_mask);
    for (unsigned int index = 0u; index < 16u; index++) ciphertext_and_tag[plain_size + index] = (unsigned char)(ghash[index] ^ tag_mask[index]);
    ok = 1;

cleanup:
    bench_secure_zero(zero, sizeof(zero));
    bench_secure_zero(hash_subkey, sizeof(hash_subkey));
    bench_secure_zero(ghash, sizeof(ghash));
    bench_secure_zero(j0, sizeof(j0));
    bench_secure_zero(counter, sizeof(counter));
    bench_secure_zero(stream, sizeof(stream));
    bench_secure_zero(tag_mask, sizeof(tag_mask));
    bench_secure_zero(lengths, sizeof(lengths));
    return ok;
}

static void bench_page_material(bench_gcm_page *page, size_t size, unsigned int index) {
    uint64_t marker = bench_mix(((uint64_t)size << 8u) ^ (uint64_t)(index + 1u));
    if (!page) return;
    for (unsigned int offset = 0u; offset < sizeof(page->nonce); offset++) {
        page->nonce[offset] = (unsigned char)(marker >> ((offset & 7u) * 8u));
        marker = bench_mix(marker ^ offset);
    }
    for (unsigned int offset = 0u; offset < sizeof(page->aad); offset++) {
        page->aad[offset] = (unsigned char)(marker >> ((offset & 7u) * 8u));
        marker = bench_mix(marker ^ ((uint64_t)size + offset));
    }
    page->aad_size = sizeof(page->aad);
}

static void bench_gcm_page_clear(bench_fixture_counters *fixture, bench_gcm_page *page) {
    if (!page) return;
    bench_wipe_free(fixture, page->ciphertext_and_tag, page->ciphertext_and_tag_size);
    bench_secure_zero(page, sizeof(*page));
}

static int bench_gcm_page_prepare(bench_state *state, bench_gcm_page *page, size_t size, unsigned int page_index) {
    unsigned char *plain = NULL;
    uint64_t expected_digest = 0u;
    if (!state || !page || !state->scratch || state->scratch_capacity < size || size > SIZE_MAX - 16u) return 0;
    memset(page, 0, sizeof(*page));
    page->plain_size = size;
    page->ciphertext_and_tag_size = size + 16u;
    bench_page_material(page, size, page_index);
    plain = (unsigned char *)bench_alloc(&state->fixture, size);
    page->ciphertext_and_tag = (unsigned char *)bench_alloc(&state->fixture, page->ciphertext_and_tag_size);
    if (!plain || !page->ciphertext_and_tag) goto failure;
    bench_fill(plain, size, UINT64_C(0x8f3d9c2a7b6e5140) ^ (uint64_t)page_index);
    expected_digest = bench_output_digest(plain, size);
    if (!bench_gcm128_encrypt(
            BENCH_GCM_KEY_128,
            page->nonce,
            page->aad,
            page->aad_size,
            plain,
            size,
            page->ciphertext_and_tag
        )) goto failure;
    if (!js_aes_gcm_decrypt(
            BENCH_GCM_KEY_128,
            sizeof(BENCH_GCM_KEY_128),
            page->nonce,
            page->aad,
            page->aad_size,
            page->ciphertext_and_tag,
            page->ciphertext_and_tag_size,
            state->scratch
        )) goto failure;
    if (bench_output_digest(state->scratch, size) != expected_digest) goto failure;
    js_vbc4_wipe_volatile(state->scratch, size);
    bench_wipe_free(&state->fixture, plain, size);
    page->expected_digest = expected_digest;
    return 1;

failure:
    ++state->fixture.exception_count;
    if (state->scratch) js_vbc4_wipe_volatile(state->scratch, size);
    bench_wipe_free(&state->fixture, plain, size);
    bench_gcm_page_clear(&state->fixture, page);
    return 0;
}

static void bench_shell_payload_clear(bench_fixture_counters *fixture, bench_shell_payload *payload) {
    if (!payload) return;
    bench_wipe_free(fixture, payload->encoded, payload->size);
    bench_wipe_free(fixture, payload->chunk_tags, payload->chunk_tags_size);
    bench_secure_zero(payload, sizeof(*payload));
}

static int bench_shell_encode_payload(
    unsigned char *encoded,
    size_t size,
    unsigned int chunk_size,
    unsigned char *chunk_tags,
    size_t chunk_tags_size
) {
    size_t chunk_count;
    if (!encoded || !chunk_tags || chunk_size == 0u) return 0;
    chunk_count = 1u + (size - 1u) / (size_t)chunk_size;
    if (chunk_count > SIZE_MAX / 32u || chunk_tags_size != chunk_count * 32u || chunk_count > UINT_MAX) return 0;
    for (size_t chunk_index = 0u; chunk_index < chunk_count; chunk_index++) {
        unsigned char chunk_key[32] = {0};
        unsigned char tag_key[32] = {0};
        unsigned char iv_material[32] = {0};
        size_t offset = chunk_index * (size_t)chunk_size;
        size_t length = size - offset;
        if (length > (size_t)chunk_size) length = (size_t)chunk_size;
        js_shell_kdf(BENCH_SHELL_STREAM_KEY, "javashroud-aken-v4-native-shell-chunk-aes-v1", BENCH_SHELL_NONCE, BENCH_SHELL_BINDING_TAG, (unsigned int)chunk_index, chunk_key);
        js_shell_kdf(BENCH_SHELL_STREAM_KEY, "javashroud-aken-v4-native-shell-chunk-hmac-v1", BENCH_SHELL_NONCE, BENCH_SHELL_BINDING_TAG, (unsigned int)chunk_index, tag_key);
        js_shell_kdf(BENCH_SHELL_STREAM_KEY, "javashroud-aken-v4-native-shell-chunk-iv-v1", BENCH_SHELL_NONCE, BENCH_SHELL_BINDING_TAG, (unsigned int)chunk_index, iv_material);
        js_shell_aes128_ctr_xor(encoded + offset, length, chunk_key, iv_material);
        js_shell_hmac_sha256(tag_key, sizeof(tag_key), encoded + offset, length, chunk_tags + chunk_index * 32u);
        bench_secure_zero(chunk_key, sizeof(chunk_key));
        bench_secure_zero(tag_key, sizeof(tag_key));
        bench_secure_zero(iv_material, sizeof(iv_material));
    }
    return 1;
}

static int bench_shell_payload_prepare(bench_state *state, bench_shell_payload *payload, size_t size, unsigned int payload_index) {
    unsigned char *plain = NULL;
    size_t chunk_count;
    if (!state || !payload || !state->scratch || state->scratch_capacity < size || size == 0u) return 0;
    memset(payload, 0, sizeof(*payload));
    payload->size = size;
    payload->chunk_size = BENCH_SHELL_CHUNK_SIZE;
    chunk_count = 1u + (size - 1u) / (size_t)payload->chunk_size;
    if (chunk_count > SIZE_MAX / 32u) goto failure;
    payload->chunk_tags_size = chunk_count * 32u;
    plain = (unsigned char *)bench_alloc(&state->fixture, size);
    payload->encoded = (unsigned char *)bench_alloc(&state->fixture, size);
    payload->chunk_tags = (unsigned char *)bench_alloc(&state->fixture, payload->chunk_tags_size);
    if (!plain || !payload->encoded || !payload->chunk_tags) goto failure;
    bench_fill(plain, size, UINT64_C(0x541a79e3d09c2fb6) ^ (uint64_t)payload_index);
    payload->expected_digest = bench_output_digest(plain, size);
    memcpy(payload->encoded, plain, size);
    if (!bench_shell_encode_payload(payload->encoded, size, payload->chunk_size, payload->chunk_tags, payload->chunk_tags_size)) goto failure;
    memcpy(state->scratch, payload->encoded, size);
    if (!js_shell_decode_payload_chunks(
            state->scratch,
            size,
            BENCH_SHELL_STREAM_KEY,
            BENCH_SHELL_NONCE,
            BENCH_SHELL_BINDING_TAG,
            payload->chunk_size,
            payload->chunk_tags,
            payload->chunk_tags_size
        )) goto failure;
    if (bench_output_digest(state->scratch, size) != payload->expected_digest) goto failure;
    js_vbc4_wipe_volatile(state->scratch, size);
    bench_wipe_free(&state->fixture, plain, size);
    return 1;

failure:
    ++state->fixture.exception_count;
    if (state->scratch) js_vbc4_wipe_volatile(state->scratch, size);
    bench_wipe_free(&state->fixture, plain, size);
    bench_shell_payload_clear(&state->fixture, payload);
    return 0;
}

static void bench_state_clear(bench_state *state) {
    if (!state) return;
    for (unsigned int index = 0u; index < BENCH_PAGE_COUNT; index++) {
        bench_gcm_page_clear(&state->fixture, &state->pages[index]);
        bench_shell_payload_clear(&state->fixture, &state->shell_payloads[index]);
    }
    bench_wipe_free(&state->fixture, state->scratch, state->scratch_capacity);
    bench_wipe_free(&state->fixture, state->timing_samples, state->timing_capacity * sizeof(*state->timing_samples));
    bench_secure_zero(state, sizeof(*state));
}

static int bench_state_init(bench_state *state, unsigned int samples) {
    if (!state || samples == 0u || samples > BENCH_MAX_SAMPLES) return 0;
    memset(state, 0, sizeof(*state));
    state->timing_capacity = samples;
    state->scratch_capacity = BENCH_PAGE_1M;
    state->timing_samples = (uint64_t *)bench_alloc(&state->fixture, samples * sizeof(*state->timing_samples));
    state->scratch = (unsigned char *)bench_alloc(&state->fixture, state->scratch_capacity);
    if (!state->timing_samples || !state->scratch) goto failure;
    for (unsigned int index = 0u; index < BENCH_PAGE_COUNT; index++) {
        if (!bench_gcm_page_prepare(state, &state->pages[index], BENCH_PAGE_SIZES[index], index)) goto failure;
        if (!bench_shell_payload_prepare(state, &state->shell_payloads[index], BENCH_PAGE_SIZES[index], index)) goto failure;
    }
    /* Fixture preparation must not pollute timed sample counters. */
    js_crypto_runtime_metrics_reset();
    return 1;

failure:
    bench_state_clear(state);
    return 0;
}

static void bench_phase_report_mode(
    FILE *out,
    const char *name,
    unsigned int samples,
    unsigned int warmup,
    const bench_series *series,
    bench_latency latency,
    const js_crypto_runtime_metrics *metrics,
    const bench_fixture_counters *fixture,
    const char *phase_mode,
    const char *phase_status
) {
    uint64_t exception_count;
    if (!out || !name || !series || !metrics || !fixture || !phase_mode || !phase_status) return;
    exception_count = metrics->exception_count + fixture->exception_count;
    fprintf(out,
        "phase=%s phase_mode=%s phase_status=%s timing_unit=ns percentile=nearest-rank samples=%u warmup=%u warmup_excluded=1 "
        "p50=%llu p95=%llu p99=%llu max=%llu output_digest=%016llx "
        "allocation_count=%llu allocation_bytes=%llu exception_count=%llu native_exception_count=%llu "
        "hardware_crypto_path=%llu software_crypto_path=%llu aes_block_count=%llu ghash_block_count=%llu "
        "vm_frame_reuse_count=%llu vm_heap_fallback_count=%llu resource_index_hit_count=%llu "
        "decompress_context_reuse_count=%llu jni_cache_hit_count=%llu "
        "auth_check_count=%llu auth_failure_count=%llu digest_check_count=%llu tag_check_count=%llu "
        "length_check_count=%llu structure_check_count=%llu jni_abi_check_count=%llu wipe_count=%llu "
        "wipe_failure_count=%llu plaintext_persistence_bytes=%llu fallback_count=%llu legacy_path_hits=%llu "
        "security_checks_skipped=%llu\n",
        name,
        phase_mode,
        phase_status,
        samples,
        warmup,
        (unsigned long long)latency.p50,
        (unsigned long long)latency.p95,
        (unsigned long long)latency.p99,
        (unsigned long long)latency.max,
        (unsigned long long)series->digest,
        (unsigned long long)fixture->allocation_count,
        (unsigned long long)fixture->allocation_bytes,
        (unsigned long long)exception_count,
        (unsigned long long)metrics->exception_count,
        (unsigned long long)metrics->hardware_crypto_path,
        (unsigned long long)metrics->software_crypto_path,
        (unsigned long long)metrics->aes_block_count,
        (unsigned long long)metrics->ghash_block_count,
        (unsigned long long)metrics->vm_frame_reuse_count,
        (unsigned long long)metrics->vm_heap_fallback_count,
        (unsigned long long)metrics->resource_index_hit_count,
        (unsigned long long)metrics->decompress_context_reuse_count,
        (unsigned long long)metrics->jni_cache_hit_count,
        (unsigned long long)metrics->auth_check_count,
        (unsigned long long)metrics->auth_failure_count,
        (unsigned long long)metrics->digest_check_count,
        (unsigned long long)metrics->tag_check_count,
        (unsigned long long)metrics->length_check_count,
        (unsigned long long)metrics->structure_check_count,
        (unsigned long long)metrics->jni_abi_check_count,
        (unsigned long long)metrics->wipe_count,
        (unsigned long long)metrics->wipe_failure_count,
        (unsigned long long)metrics->plaintext_persistence_bytes,
        (unsigned long long)metrics->fallback_count,
        (unsigned long long)metrics->legacy_path_hits,
        (unsigned long long)metrics->security_checks_skipped);
}

static void bench_phase_report(
    FILE *out,
    const char *name,
    unsigned int samples,
    unsigned int warmup,
    const bench_series *series,
    bench_latency latency,
    const js_crypto_runtime_metrics *metrics,
    const bench_fixture_counters *fixture
) {
    bench_phase_report_mode(out, name, samples, warmup, series, latency, metrics, fixture, "production", "pass");
}

static void bench_summary_record(
    bench_summary *summary,
    const char *phase_name,
    const bench_series *series,
    bench_latency latency,
    const js_crypto_runtime_metrics *metrics,
    const bench_fixture_counters *fixture
) {
    if (!summary || !phase_name || !series || !metrics || !fixture) return;
    bench_metrics_add(&summary->metrics, metrics);
    summary->fixture.allocation_count += fixture->allocation_count;
    summary->fixture.allocation_bytes += fixture->allocation_bytes;
    summary->fixture.free_count += fixture->free_count;
    summary->fixture.exception_count += fixture->exception_count;
    if (summary->phase_count < BENCH_MAX_PHASES) summary->phase_latency[summary->phase_count++] = latency;
    summary->output_digest = bench_mix(summary->output_digest ^ bench_text_digest(phase_name) ^ series->digest);
}

static void bench_summary_record_synthetic(
    bench_summary *summary,
    const char *phase_name,
    const bench_series *series,
    bench_latency latency,
    const js_crypto_runtime_metrics *metrics,
    const bench_fixture_counters *fixture
) {
    if (!summary || !phase_name || !series || !metrics || !fixture) return;
    bench_summary_record(summary, phase_name, series, latency, metrics, fixture);
    ++summary->synthetic_phase_count;
    ++summary->required_production_nonproduction_phase_count;
}

static void bench_unsupported_phase_report(
    FILE *out,
    bench_summary *summary,
    const char *name,
    const char *reason
) {
    if (!out || !summary || !name || !reason) return;
    fprintf(out,
        "phase=%s phase_mode=integration-adapter phase_status=unsupported reason=%s "
        "security_gate=not-applicable output_digest=%016llx\n",
        name,
        reason,
        (unsigned long long)bench_text_digest(name));
    ++summary->unsupported_phase_count;
    ++summary->required_production_nonproduction_phase_count;
    summary->output_digest = bench_mix(summary->output_digest ^ bench_text_digest(name) ^ bench_text_digest(reason));
}

static int bench_run_gcm_kat_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    const unsigned char *key,
    size_t key_size,
    const unsigned char ciphertext_and_tag[32],
    unsigned int samples,
    unsigned int warmup
) {
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || !key || !ciphertext_and_tag) return 0;
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        int ok = js_aes_gcm_decrypt(key, key_size, BENCH_GCM_NONCE_ZERO, NULL, 0u, ciphertext_and_tag, 32u, state->scratch);
        js_vbc4_wipe_volatile(state->scratch, 16u);
        if (!ok) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        uint64_t started = bench_ticks();
        int ok = js_aes_gcm_decrypt(key, key_size, BENCH_GCM_NONCE_ZERO, NULL, 0u, ciphertext_and_tag, 32u, state->scratch);
        uint64_t elapsed = bench_elapsed_ns(bench_ticks() - started);
        uint64_t output = ok ? bench_output_digest(state->scratch, 16u) : 0u;
        js_vbc4_wipe_volatile(state->scratch, 16u);
        if (!ok || !bench_series_record(&series, elapsed, output ^ (uint64_t)(ok ? 1u : 0u))) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
    bench_phase_report(out, name, samples, warmup, &series, latency, &delta, &fixture_delta);
    bench_summary_record(summary, name, &series, latency, &delta, &fixture_delta);
    return 1;
}

static int bench_run_gcm_page_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    const bench_gcm_page *page,
    unsigned int samples,
    unsigned int warmup
) {
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || !page || !page->ciphertext_and_tag) return 0;
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        int ok = js_aes_gcm_decrypt(BENCH_GCM_KEY_128, sizeof(BENCH_GCM_KEY_128), page->nonce, page->aad, page->aad_size,
            page->ciphertext_and_tag, page->ciphertext_and_tag_size, state->scratch);
        js_vbc4_wipe_volatile(state->scratch, page->plain_size);
        if (!ok) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        uint64_t started = bench_ticks();
        int ok = js_aes_gcm_decrypt(BENCH_GCM_KEY_128, sizeof(BENCH_GCM_KEY_128), page->nonce, page->aad, page->aad_size,
            page->ciphertext_and_tag, page->ciphertext_and_tag_size, state->scratch);
        uint64_t elapsed = bench_elapsed_ns(bench_ticks() - started);
        uint64_t output = ok ? bench_output_digest(state->scratch, page->plain_size) : 0u;
        int digest_matches = ok && output == page->expected_digest;
        js_vbc4_wipe_volatile(state->scratch, page->plain_size);
        if (!digest_matches || !bench_series_record(&series, elapsed, output ^ (uint64_t)(digest_matches ? 1u : 0u))) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
    /* This fixture invokes the real GCM hot path, but it has no current AKEN
     * locator, descriptor, proof, route, or bound-plan session. It is timing
     * evidence for crypto only, never a production AKEN page-open claim. */
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "synthetic-fixture", "pass");
    bench_summary_record_synthetic(summary, name, &series, latency, &delta, &fixture_delta);
    return 1;
}

static int bench_run_ctr_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    const unsigned char *key,
    size_t key_size,
    size_t size,
    unsigned int samples,
    unsigned int warmup
) {
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || !key || size > state->scratch_capacity) return 0;
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        bench_fill(state->scratch, size, UINT64_C(0x2d5a97c134fe806b) ^ iteration);
        js_aes_ctr_xor(state->scratch, size, key, key_size, BENCH_CTR_IV);
        js_vbc4_wipe_volatile(state->scratch, size);
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        uint64_t started;
        uint64_t elapsed;
        uint64_t output;
        bench_fill(state->scratch, size, UINT64_C(0x2d5a97c134fe806b) ^ iteration);
        started = bench_ticks();
        js_aes_ctr_xor(state->scratch, size, key, key_size, BENCH_CTR_IV);
        elapsed = bench_elapsed_ns(bench_ticks() - started);
        output = bench_output_digest(state->scratch, size);
        js_vbc4_wipe_volatile(state->scratch, size);
        if (!bench_series_record(&series, elapsed, output)) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
    bench_phase_report(out, name, samples, warmup, &series, latency, &delta, &fixture_delta);
    bench_summary_record(summary, name, &series, latency, &delta, &fixture_delta);
    return 1;
}

static int bench_run_shell_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    const bench_shell_payload *payload,
    unsigned int samples,
    unsigned int warmup
) {
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || !payload || !payload->encoded || !payload->chunk_tags || payload->size > state->scratch_capacity) return 0;
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        int ok;
        memcpy(state->scratch, payload->encoded, payload->size);
        ok = js_shell_decode_payload_chunks(state->scratch, payload->size, BENCH_SHELL_STREAM_KEY, BENCH_SHELL_NONCE,
            BENCH_SHELL_BINDING_TAG, payload->chunk_size, payload->chunk_tags, payload->chunk_tags_size);
        js_vbc4_wipe_volatile(state->scratch, payload->size);
        if (!ok) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        uint64_t started;
        uint64_t elapsed;
        uint64_t output;
        int ok;
        int digest_matches;
        memcpy(state->scratch, payload->encoded, payload->size);
        started = bench_ticks();
        ok = js_shell_decode_payload_chunks(state->scratch, payload->size, BENCH_SHELL_STREAM_KEY, BENCH_SHELL_NONCE,
            BENCH_SHELL_BINDING_TAG, payload->chunk_size, payload->chunk_tags, payload->chunk_tags_size);
        elapsed = bench_elapsed_ns(bench_ticks() - started);
        output = ok ? bench_output_digest(state->scratch, payload->size) : 0u;
        digest_matches = ok && output == payload->expected_digest;
        js_vbc4_wipe_volatile(state->scratch, payload->size);
        if (!digest_matches || !bench_series_record(&series, elapsed, output ^ (uint64_t)(digest_matches ? 1u : 0u))) {
            ++state->fixture.exception_count;
            return 0;
        }
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
    /* Decode/auth is real native code, but the fixture cannot establish a
     * production shell's verified mapping and loader lifecycle. */
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "synthetic-fixture", "pass");
    bench_summary_record_synthetic(summary, name, &series, latency, &delta, &fixture_delta);
    return 1;
}

static int bench_run_resource_index_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    uint64_t domain,
    unsigned int samples,
    unsigned int warmup
) {
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
    bench_production_resource_fixture production_fixture;
    int production = 0;
#else
    bench_resource_index index;
#endif
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || samples == 0u) return 0;
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
    production = strcmp(name, "resource-alias-lookup") == 0 || strcmp(name, "resource-commitment-lookup") == 0;
    if (!production || !bench_production_resource_fixture_prepare(&production_fixture)) {
        ++state->fixture.exception_count;
        return 0;
    }
#else
    if (!bench_resource_index_prepare(&index, domain)) {
        ++state->fixture.exception_count;
        return 0;
    }
#endif
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        uint32_t identity = 0u;
        uint64_t hash = bench_mix(domain ^ ((uint64_t)(iteration % BENCH_RESOURCE_INDEX_COUNT) + UINT64_C(0x1001)));
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
        char resolved_path[JS_VM_CALL_GATE_KEY_LEN];
        int found = 0;
        (void)identity;
        (void)hash;
        memset(resolved_path, 0, sizeof(resolved_path));
        if (strcmp(name, "resource-alias-lookup") == 0) {
            found = js_vm_resource_alias_resolve_copy(production_fixture.alias, resolved_path, sizeof(resolved_path));
            found = found && strcmp(resolved_path, production_fixture.path) == 0;
        } else {
            found = js_vm_commitment_matches(
                production_fixture.path,
                production_fixture.raw,
                (int)production_fixture.raw_len);
        }
        bench_secure_zero(resolved_path, sizeof(resolved_path));
        if (!found) {
            ++state->fixture.exception_count;
            js_vm_call_gate_reset();
            bench_secure_zero(&production_fixture, sizeof(production_fixture));
            return 0;
        }
#else
        if (!bench_resource_index_lookup(&index, hash, &identity) || identity == 0u) {
            ++state->fixture.exception_count;
            bench_secure_zero(&index, sizeof(index));
            return 0;
        }
#endif
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        uint32_t identity = 0u;
        uint64_t hash = bench_mix(domain ^ ((uint64_t)(iteration % BENCH_RESOURCE_INDEX_COUNT) + UINT64_C(0x1001)));
        uint64_t started = bench_ticks();
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
        char resolved_path[JS_VM_CALL_GATE_KEY_LEN];
        int found = 0;
        (void)identity;
        (void)hash;
        memset(resolved_path, 0, sizeof(resolved_path));
        if (strcmp(name, "resource-alias-lookup") == 0) {
            found = js_vm_resource_alias_resolve_copy(production_fixture.alias, resolved_path, sizeof(resolved_path));
            found = found && strcmp(resolved_path, production_fixture.path) == 0;
        } else {
            found = js_vm_commitment_matches(
                production_fixture.path,
                production_fixture.raw,
                (int)production_fixture.raw_len);
        }
        bench_secure_zero(resolved_path, sizeof(resolved_path));
#else
        int found = bench_resource_index_lookup(&index, hash, &identity);
#endif
        uint64_t elapsed = bench_elapsed_ns(bench_ticks() - started);
 #if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
        if (!found) {
            ++state->fixture.exception_count;
            js_vm_call_gate_reset();
            bench_secure_zero(&production_fixture, sizeof(production_fixture));
            return 0;
        }
 #else
        if (!found || identity == 0u) {
            ++state->fixture.exception_count;
            bench_secure_zero(&index, sizeof(index));
            return 0;
        }
 #endif
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
        if (!bench_series_record(
                &series,
                elapsed,
                bench_mix((uint64_t)(found ? 1u : 0u) ^ (uint64_t)(iteration + 1u)))) {
#else
        js_runtime_metrics_note_resource_index_hit();
        if (!bench_series_record(&series, elapsed, bench_mix(hash ^ identity))) {
#endif
            ++state->fixture.exception_count;
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
            js_vm_call_gate_reset();
            bench_secure_zero(&production_fixture, sizeof(production_fixture));
#else
            bench_secure_zero(&index, sizeof(index));
#endif
            return 0;
        }
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "production", "pass");
    bench_summary_record(summary, name, &series, latency, &delta, &fixture_delta);
    js_vm_call_gate_reset();
    bench_secure_zero(&production_fixture, sizeof(production_fixture));
#else
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "synthetic-fixture", "pass");
    bench_summary_record_synthetic(summary, name, &series, latency, &delta, &fixture_delta);
    bench_secure_zero(&index, sizeof(index));
#endif
    return 1;
}

static int bench_run_jni_cache_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    unsigned int samples,
    unsigned int warmup
) {
    bench_jni_cache_fixture cache;
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || samples == 0u || !bench_jni_cache_fixture_prepare(&cache)) return 0;
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        if (!cache.valid || cache.abi_generation != 1u || cache.session_generation != 1u ||
            cache.loader_identity == 0u || cache.class_identity == 0u || cache.method_identity == 0u) {
            ++state->fixture.exception_count;
            bench_secure_zero(&cache, sizeof(cache));
            return 0;
        }
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        uint64_t started = bench_ticks();
        int valid = cache.valid && cache.abi_generation == 1u && cache.session_generation == 1u &&
            cache.loader_identity != 0u && cache.class_identity != 0u && cache.method_identity != 0u;
        uint64_t elapsed = bench_elapsed_ns(bench_ticks() - started);
        if (!valid) {
            ++state->fixture.exception_count;
            bench_secure_zero(&cache, sizeof(cache));
            return 0;
        }
        js_runtime_metrics_note_jni_cache_hit();
        if (!bench_series_record(&series, elapsed, bench_mix(cache.loader_identity ^ cache.class_identity ^ cache.method_identity))) {
            ++state->fixture.exception_count;
            bench_secure_zero(&cache, sizeof(cache));
            return 0;
        }
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "synthetic-fixture", "pass");
    bench_summary_record_synthetic(summary, name, &series, latency, &delta, &fixture_delta);
    bench_secure_zero(&cache, sizeof(cache));
    return 1;
}

static int bench_run_zstd_context_phase(
    FILE *out,
    bench_state *state,
    bench_summary *summary,
    const char *name,
    unsigned int samples,
    unsigned int warmup
) {
#if defined(JS_RUNTIME_BENCH_RESOURCE_RUNTIME)
    static const unsigned char compressed_zeros[19u] = {
        0x28, 0xb5, 0x2f, 0xfd, 0x60, 0x00, 0x0f, 0x4d, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x01, 0x00, 0xfb, 0xf7, 0x01, 0x16
    };
    unsigned char corrupt_compressed[sizeof(compressed_zeros)];
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    js_crypto_runtime_metrics reset_metrics, failure_metrics;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    uint64_t expected_reuse_count;
    int ok = 0;
    memset(corrupt_compressed, 0, sizeof(corrupt_compressed));
    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    memset(&delta, 0, sizeof(delta));
    memset(&reset_metrics, 0, sizeof(reset_metrics));
    memset(&failure_metrics, 0, sizeof(failure_metrics));
    if (!out || !state || !summary || !name || samples == 0u) return 0;

    /* This is the production resource-owned decoder.  Reset before warmup so
     * a context from a prior artifact/session cannot contribute a false reuse. */
    js_vm_call_gate_reset();
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        unsigned char *plain = js_vbc4_zstd_decompress_owned(
            compressed_zeros,
            (uint32_t)sizeof(compressed_zeros),
            BENCH_ZSTD_PLAIN_SIZE);
        if (!plain || bench_output_digest(plain, BENCH_ZSTD_PLAIN_SIZE) != UINT64_C(0x549ddf54be5240d0)) {
            if (plain) {
                js_vbc4_wipe_volatile(plain, BENCH_ZSTD_PLAIN_SIZE);
                free(plain);
            }
            goto production_zstd_failure;
        }
        js_vbc4_wipe_volatile(plain, BENCH_ZSTD_PLAIN_SIZE);
        free(plain);
    }

    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        unsigned char *plain;
        uint64_t started = bench_ticks();
        uint64_t elapsed;
        uint64_t output;
        plain = js_vbc4_zstd_decompress_owned(
            compressed_zeros,
            (uint32_t)sizeof(compressed_zeros),
            BENCH_ZSTD_PLAIN_SIZE);
        elapsed = bench_elapsed_ns(bench_ticks() - started);
        if (!plain) goto production_zstd_failure;
        output = bench_output_digest(plain, BENCH_ZSTD_PLAIN_SIZE);
        if (output != UINT64_C(0x549ddf54be5240d0) ||
            !bench_series_record(&series, elapsed, output)) {
            js_vbc4_wipe_volatile(plain, BENCH_ZSTD_PLAIN_SIZE);
            free(plain);
            goto production_zstd_failure;
        }
        js_vbc4_wipe_volatile(plain, BENCH_ZSTD_PLAIN_SIZE);
        free(plain);
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    expected_reuse_count = warmup == 0u ? (samples > 0u ? (uint64_t)samples - 1u : 0u) : (uint64_t)samples;
    if (delta.decompress_context_reuse_count != expected_reuse_count ||
        delta.fallback_count != 0u || delta.legacy_path_hits != 0u ||
        delta.wipe_failure_count != 0u || delta.plaintext_persistence_bytes != 0u ||
        delta.security_checks_skipped != 0u || delta.exception_count != 0u) {
        goto production_zstd_failure;
    }
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);

    /* Session reset must retire the old FLS/TLS decoder.  The first decode of
     * the next generation has to allocate a fresh context, not report reuse. */
    js_vm_call_gate_reset();
    js_crypto_runtime_metrics_reset();
    {
        unsigned char *plain = js_vbc4_zstd_decompress_owned(
            compressed_zeros,
            (uint32_t)sizeof(compressed_zeros),
            BENCH_ZSTD_PLAIN_SIZE);
        if (!plain || bench_output_digest(plain, BENCH_ZSTD_PLAIN_SIZE) != UINT64_C(0x549ddf54be5240d0)) {
            if (plain) {
                js_vbc4_wipe_volatile(plain, BENCH_ZSTD_PLAIN_SIZE);
                free(plain);
            }
            goto production_zstd_failure;
        }
        js_vbc4_wipe_volatile(plain, BENCH_ZSTD_PLAIN_SIZE);
        free(plain);
    }
    js_crypto_runtime_metrics_snapshot(&reset_metrics);
    if (reset_metrics.decompress_context_reuse_count != 0u ||
        reset_metrics.structure_check_count == 0u || reset_metrics.length_check_count == 0u ||
        reset_metrics.fallback_count != 0u || reset_metrics.legacy_path_hits != 0u ||
        reset_metrics.wipe_failure_count != 0u || reset_metrics.plaintext_persistence_bytes != 0u ||
        reset_metrics.security_checks_skipped != 0u || reset_metrics.exception_count != 0u) {
        goto production_zstd_failure;
    }

    /* A decoder failure must wipe the owned partial output.  The invalid frame
     * remains stack-owned and is wiped before this phase returns. */
    memcpy(corrupt_compressed, compressed_zeros, sizeof(corrupt_compressed));
    corrupt_compressed[0] ^= 0x01u;
    {
        unsigned char *unexpected_plain = js_vbc4_zstd_decompress_owned(
            corrupt_compressed,
            (uint32_t)sizeof(corrupt_compressed),
            BENCH_ZSTD_PLAIN_SIZE);
        if (unexpected_plain) {
            js_vbc4_wipe_volatile(unexpected_plain, BENCH_ZSTD_PLAIN_SIZE);
            free(unexpected_plain);
            goto production_zstd_failure;
        }
    }
    js_crypto_runtime_metrics_snapshot(&failure_metrics);
    if (failure_metrics.wipe_count <= reset_metrics.wipe_count ||
        failure_metrics.decompress_context_reuse_count != 1u ||
        failure_metrics.fallback_count != 0u || failure_metrics.legacy_path_hits != 0u ||
        failure_metrics.wipe_failure_count != 0u || failure_metrics.plaintext_persistence_bytes != 0u ||
        failure_metrics.security_checks_skipped != 0u || failure_metrics.exception_count != 0u) {
        goto production_zstd_failure;
    }

    fprintf(out,
        "zstd_lifecycle phase_name=%s phase_mode=production status=pass "
        "post_reset_reuse_count=%llu failure_reuse_count=%llu failure_wipe_delta=%llu "
        "fallback_count=%llu legacy_path_hits=%llu wipe_failure_count=%llu "
        "plaintext_persistence_bytes=%llu security_checks_skipped=%llu exception_count=%llu\n",
        name,
        (unsigned long long)reset_metrics.decompress_context_reuse_count,
        (unsigned long long)failure_metrics.decompress_context_reuse_count,
        (unsigned long long)(failure_metrics.wipe_count - reset_metrics.wipe_count),
        (unsigned long long)failure_metrics.fallback_count,
        (unsigned long long)failure_metrics.legacy_path_hits,
        (unsigned long long)failure_metrics.wipe_failure_count,
        (unsigned long long)failure_metrics.plaintext_persistence_bytes,
        (unsigned long long)failure_metrics.security_checks_skipped,
        (unsigned long long)failure_metrics.exception_count);
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "production", "pass");
    bench_summary_record(summary, name, &series, latency, &delta, &fixture_delta);
    ok = 1;

production_zstd_failure:
    js_vm_call_gate_reset();
    bench_secure_zero(corrupt_compressed, sizeof(corrupt_compressed));
    if (!ok) ++state->fixture.exception_count;
    return ok;
#elif !defined(JS_RUNTIME_BENCH_ZSTD)
    (void)state;
    (void)samples;
    (void)warmup;
    bench_unsupported_phase_report(out, summary, name, "requires-zstd-integration-build");
    return 1;
#else
    static const unsigned char compressed_zeros[19u] = {
        0x28, 0xb5, 0x2f, 0xfd, 0x60, 0x00, 0x0f, 0x4d, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x01, 0x00, 0xfb, 0xf7, 0x01, 0x16
    };
    ZSTD_DCtx *context = NULL;
    bench_series series;
    js_crypto_runtime_metrics before, after, delta;
    bench_fixture_counters fixture_before, fixture_delta;
    bench_latency latency;
    if (!out || !state || !summary || !name || samples == 0u || state->scratch_capacity < BENCH_ZSTD_PLAIN_SIZE) return 0;
    context = ZSTD_createDCtx();
    if (!context) {
        ++state->fixture.exception_count;
        return 0;
    }
    for (unsigned int iteration = 0u; iteration < warmup; iteration++) {
        size_t reset_status = ZSTD_DCtx_reset(context, ZSTD_reset_session_only);
        size_t written;
        if (ZSTD_isError(reset_status)) goto zstd_failure;
        written = ZSTD_decompressDCtx(context, state->scratch, BENCH_ZSTD_PLAIN_SIZE, compressed_zeros, sizeof(compressed_zeros));
        if (ZSTD_isError(written) || written != BENCH_ZSTD_PLAIN_SIZE || bench_output_digest(state->scratch, written) != UINT64_C(0x549ddf54be5240d0)) goto zstd_failure;
        js_vbc4_wipe_volatile(state->scratch, written);
    }
    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&before);
    fixture_before = state->fixture;
    bench_series_begin(&series, state->timing_samples, state->timing_capacity, name);
    for (unsigned int iteration = 0u; iteration < samples; iteration++) {
        size_t reset_status = ZSTD_DCtx_reset(context, ZSTD_reset_session_only);
        uint64_t started;
        size_t written;
        uint64_t elapsed;
        if (ZSTD_isError(reset_status)) goto zstd_failure;
        started = bench_ticks();
        written = ZSTD_decompressDCtx(context, state->scratch, BENCH_ZSTD_PLAIN_SIZE, compressed_zeros, sizeof(compressed_zeros));
        elapsed = bench_elapsed_ns(bench_ticks() - started);
        if (ZSTD_isError(written) || written != BENCH_ZSTD_PLAIN_SIZE || bench_output_digest(state->scratch, written) != UINT64_C(0x549ddf54be5240d0)) goto zstd_failure;
        js_runtime_metrics_note_decompress_context_reuse();
        if (!bench_series_record(&series, elapsed, bench_output_digest(state->scratch, written))) goto zstd_failure;
        js_vbc4_wipe_volatile(state->scratch, written);
    }
    js_crypto_runtime_metrics_snapshot(&after);
    bench_metrics_delta(&delta, &before, &after);
    bench_fixture_delta(&fixture_delta, &fixture_before, &state->fixture);
    latency = bench_series_finish(&series);
    bench_phase_report_mode(out, name, samples, warmup, &series, latency, &delta, &fixture_delta, "synthetic-fixture", "pass");
    bench_summary_record_synthetic(summary, name, &series, latency, &delta, &fixture_delta);
    ZSTD_freeDCtx(context);
    return 1;

zstd_failure:
    ++state->fixture.exception_count;
    js_vbc4_wipe_volatile(state->scratch, BENCH_ZSTD_PLAIN_SIZE);
    if (context) ZSTD_freeDCtx(context);
    return 0;
#endif
}

static const char *bench_differential_status(
    const bench_summary *summary,
    const bench_security_baseline *baseline
) {
    if (!summary || !baseline || !baseline->valid || !baseline->has_differential_output_digest) return "not-provided";
    return summary->output_digest == baseline->differential_output_digest ? "match" : "mismatch";
}

static const char *bench_security_gate_reason(
    const bench_summary *summary,
    const bench_security_baseline *baseline
) {
    const js_crypto_runtime_metrics *metrics;
    if (!summary) return "summary-missing";
    if (!baseline || !baseline->supplied) return "baseline-missing";
    if (!baseline->valid || baseline->field_mask != BENCH_BASELINE_REQUIRED_MASK) return "baseline-invalid";
    metrics = &summary->metrics;
    if (summary->fixture.exception_count != 0u || metrics->exception_count != 0u) return "exception-count";
    if (metrics->auth_failure_count != 0u) return "auth-failure";
    if (metrics->wipe_failure_count != 0u) return "wipe-failure";
    if (metrics->plaintext_persistence_bytes != 0u) return "plaintext-persistence";
    if (metrics->fallback_count != 0u) return "fallback-count";
    if (metrics->legacy_path_hits != 0u) return "legacy-path";
    if (metrics->security_checks_skipped != 0u) return "security-checks-skipped";
    if (!bench_baseline_floor_met(metrics, baseline)) return "baseline-floor";
    /* A hardware-dispatch measurement is not accepted until it is bound to a
     * same-profile software-reference output digest. */
    if ((metrics->hardware_crypto_path != 0u || metrics->software_crypto_path != 0u) &&
        !baseline->has_differential_output_digest) return "hardware-software-differential-missing";
    if (baseline->has_differential_output_digest &&
        summary->output_digest != baseline->differential_output_digest) return "hardware-software-differential-mismatch";
    return "pass";
}

static int bench_security_gate(
    const bench_summary *summary,
    const bench_security_baseline *baseline
) {
    return strcmp(bench_security_gate_reason(summary, baseline), "pass") == 0;
}

static int bench_coverage_complete(const bench_summary *summary) {
    return summary && summary->required_production_nonproduction_phase_count == 0u;
}

static bench_result_status bench_result_status_for(
    const bench_summary *summary,
    const bench_security_baseline *baseline
) {
    if (!bench_security_gate(summary, baseline)) return BENCH_RESULT_SECURITY_BLOCKED;
    return bench_coverage_complete(summary) ? BENCH_RESULT_PASS : BENCH_RESULT_COVERAGE_INCOMPLETE;
}

static const char *bench_result_status_name(bench_result_status status) {
    switch (status) {
        case BENCH_RESULT_PASS: return "pass";
        case BENCH_RESULT_COVERAGE_INCOMPLETE: return "coverage-incomplete";
        case BENCH_RESULT_SECURITY_BLOCKED: return "security-blocked";
        default: return "security-blocked";
    }
}

static uint64_t bench_phase_percentile(const bench_summary *summary, unsigned int selector) {
    uint64_t values[BENCH_MAX_PHASES];
    if (!summary || summary->phase_count == 0u) return 0u;
    for (size_t index = 0u; index < summary->phase_count; index++) {
        values[index] = selector == 0u ? summary->phase_latency[index].p50 :
            selector == 1u ? summary->phase_latency[index].p95 : summary->phase_latency[index].max;
    }
    qsort(values, summary->phase_count, sizeof(values[0]), bench_compare_u64);
    if (selector == 0u) return values[bench_percentile_index(summary->phase_count, 500u)];
    if (selector == 1u) return values[bench_percentile_index(summary->phase_count, 950u)];
    return values[summary->phase_count - 1u];
}

static void bench_summary_report(
    FILE *out,
    const bench_state *state,
    const bench_summary *summary,
    const bench_security_baseline *baseline
) {
    const js_crypto_runtime_metrics *m;
    const char *coverage_status;
    const char *security_reason;
    const char *differential_status;
    if (!out || !state || !summary) return;
    m = &summary->metrics;
    coverage_status = bench_coverage_complete(summary) ? "complete" : "incomplete";
    security_reason = bench_security_gate_reason(summary, baseline);
    differential_status = bench_differential_status(summary, baseline);
    fprintf(out,
        "metrics hardware_crypto_path=%llu software_crypto_path=%llu aes_block_count=%llu ghash_block_count=%llu "
        "vm_frame_reuse_count=%llu vm_heap_fallback_count=%llu resource_index_hit_count=%llu "
        "decompress_context_reuse_count=%llu jni_cache_hit_count=%llu auth_check_count=%llu auth_failure_count=%llu "
        "digest_check_count=%llu tag_check_count=%llu length_check_count=%llu structure_check_count=%llu "
        "jni_abi_check_count=%llu wipe_count=%llu wipe_failure_count=%llu plaintext_persistence_bytes=%llu "
        "fallback_count=%llu legacy_path_hits=%llu exception_count=%llu security_checks_skipped=%llu "
        "phase_p50=%llu phase_p95=%llu phase_max=%llu output_digest=%016llx "
        "fixture_setup_allocation_count=%llu fixture_setup_allocation_bytes=%llu fixture_free_count=%llu fixture_exception_count=%llu "
        "synthetic_phase_count=%llu unsupported_phase_count=%llu required_production_nonproduction_phase_count=%llu coverage_status=%s\n",
        (unsigned long long)m->hardware_crypto_path,
        (unsigned long long)m->software_crypto_path,
        (unsigned long long)m->aes_block_count,
        (unsigned long long)m->ghash_block_count,
        (unsigned long long)m->vm_frame_reuse_count,
        (unsigned long long)m->vm_heap_fallback_count,
        (unsigned long long)m->resource_index_hit_count,
        (unsigned long long)m->decompress_context_reuse_count,
        (unsigned long long)m->jni_cache_hit_count,
        (unsigned long long)m->auth_check_count,
        (unsigned long long)m->auth_failure_count,
        (unsigned long long)m->digest_check_count,
        (unsigned long long)m->tag_check_count,
        (unsigned long long)m->length_check_count,
        (unsigned long long)m->structure_check_count,
        (unsigned long long)m->jni_abi_check_count,
        (unsigned long long)m->wipe_count,
        (unsigned long long)m->wipe_failure_count,
        (unsigned long long)m->plaintext_persistence_bytes,
        (unsigned long long)m->fallback_count,
        (unsigned long long)m->legacy_path_hits,
        (unsigned long long)(m->exception_count + summary->fixture.exception_count),
        (unsigned long long)m->security_checks_skipped,
        (unsigned long long)bench_phase_percentile(summary, 0u),
        (unsigned long long)bench_phase_percentile(summary, 1u),
        (unsigned long long)bench_phase_percentile(summary, 2u),
        (unsigned long long)summary->output_digest,
        (unsigned long long)state->fixture.allocation_count,
        (unsigned long long)state->fixture.allocation_bytes,
        (unsigned long long)state->fixture.free_count,
        (unsigned long long)(state->fixture.exception_count + summary->fixture.exception_count),
        (unsigned long long)summary->synthetic_phase_count,
        (unsigned long long)summary->unsupported_phase_count,
        (unsigned long long)summary->required_production_nonproduction_phase_count,
        coverage_status);
    fprintf(out,
        "baseline_security status=%s supplied=%u required_field_mask=%u auth_check_count=%llu digest_check_count=%llu "
        "tag_check_count=%llu length_check_count=%llu structure_check_count=%llu jni_abi_check_count=%llu wipe_count=%llu "
        "differential_reference_supplied=%u differential_reference_digest=%016llx differential_status=%s baseline_floor_status=%s\n",
        bench_baseline_status(baseline),
        baseline ? baseline->supplied : 0u,
        baseline ? baseline->field_mask : 0u,
        (unsigned long long)(baseline ? baseline->minimum.auth_check_count : 0u),
        (unsigned long long)(baseline ? baseline->minimum.digest_check_count : 0u),
        (unsigned long long)(baseline ? baseline->minimum.tag_check_count : 0u),
        (unsigned long long)(baseline ? baseline->minimum.length_check_count : 0u),
        (unsigned long long)(baseline ? baseline->minimum.structure_check_count : 0u),
        (unsigned long long)(baseline ? baseline->minimum.jni_abi_check_count : 0u),
        (unsigned long long)(baseline ? baseline->minimum.wipe_count : 0u),
        baseline ? baseline->has_differential_output_digest : 0u,
        (unsigned long long)(baseline ? baseline->differential_output_digest : 0u),
        differential_status,
        bench_baseline_floor_met(m, baseline) ? "met" : "not-met");
    fprintf(out,
        "coverage_gate status=%s synthetic_phase_count=%llu unsupported_phase_count=%llu "
        "required_production_nonproduction_phase_count=%llu\n",
        bench_coverage_complete(summary) ? "pass" : "coverage-incomplete",
        (unsigned long long)summary->synthetic_phase_count,
        (unsigned long long)summary->unsupported_phase_count,
        (unsigned long long)summary->required_production_nonproduction_phase_count);
    fprintf(out,
        "security_gate status=%s reason=%s auth_check_count=%llu digest_check_count=%llu tag_check_count=%llu "
        "length_check_count=%llu structure_check_count=%llu jni_abi_check_count=%llu "
        "wipe_count=%llu auth_failure_count=%llu exception_count=%llu fallback_count=%llu legacy_path_hits=%llu "
        "wipe_failure_count=%llu plaintext_persistence_bytes=%llu security_checks_skipped=%llu\n",
        bench_security_gate(summary, baseline) ? "pass" : "security-blocked",
        security_reason,
        (unsigned long long)m->auth_check_count,
        (unsigned long long)m->digest_check_count,
        (unsigned long long)m->tag_check_count,
        (unsigned long long)m->length_check_count,
        (unsigned long long)m->structure_check_count,
        (unsigned long long)m->jni_abi_check_count,
        (unsigned long long)m->wipe_count,
        (unsigned long long)m->auth_failure_count,
        (unsigned long long)(m->exception_count + summary->fixture.exception_count),
        (unsigned long long)m->fallback_count,
        (unsigned long long)m->legacy_path_hits,
        (unsigned long long)m->wipe_failure_count,
        (unsigned long long)m->plaintext_persistence_bytes,
        (unsigned long long)m->security_checks_skipped);
    fprintf(out,
        "benchmark_gate_candidate status=%s differential_status=%s\n",
        bench_result_status_name(bench_result_status_for(summary, baseline)),
        differential_status);
}

static int bench_run_one(
    FILE *out,
    unsigned int samples,
    unsigned int warmup,
    const bench_security_baseline *baseline
) {
    bench_state state;
    bench_summary summary;
    bench_result_status result_status = BENCH_RESULT_SECURITY_BLOCKED;
    int completed = 0;
    if (!out || samples == 0u || samples > BENCH_MAX_SAMPLES || warmup > BENCH_MAX_WARMUP) return 0;
    memset(&summary, 0, sizeof(summary));
    summary.output_digest = bench_mix(UINT64_C(0x13198a2e03707344) ^ samples ^ ((uint64_t)warmup << 32u));
    if (!bench_state_init(&state, samples)) {
        fprintf(out, "benchmark_result status=security-blocked reason=fixture-setup\n");
        return 0;
    }
    fprintf(out,
        "suite=native-runtime-benchmark schema=3 samples=%u warmup=%u sample_profiles=100,1000,10000,100000 "
        "pages=4096,65536,1048576 coverage=aes-gcm-128,aes-gcm-256,aes-ctr-128,aes-ctr-256,ghash-aad,authenticated-page-open,shell-payload-decode,"
        "vm-prepared-execution,vm-nested-execution,resource-alias-lookup,resource-commitment-lookup,jni-method-class-lookup,zstd-context-reuse\n",
        samples,
        warmup);
    fprintf(out,
        "capability hardware_aes=%d hardware_ghash=%d active_aes_path=reported-by-phase active_ghash_path=capability-only\n",
        js_aes_hardware_available(),
        js_ghash_hardware_available());

    if (!bench_run_gcm_kat_phase(out, &state, &summary, "aes-gcm-128-kat", BENCH_GCM_KEY_128, sizeof(BENCH_GCM_KEY_128), BENCH_GCM_128_CIPHERTEXT_AND_TAG, samples, warmup)) goto done;
    if (!bench_run_gcm_kat_phase(out, &state, &summary, "aes-gcm-256-kat", BENCH_GCM_KEY_256, sizeof(BENCH_GCM_KEY_256), BENCH_GCM_256_CIPHERTEXT_AND_TAG, samples, warmup)) goto done;
    for (unsigned int index = 0u; index < BENCH_PAGE_COUNT; index++) {
        char name[64];
        (void)snprintf(name, sizeof(name), "ghash-aad-authenticated-page-%s", index == 0u ? "4k" : index == 1u ? "64k" : "1m");
        if (!bench_run_gcm_page_phase(out, &state, &summary, name, &state.pages[index], samples, warmup)) goto done;
    }
    for (unsigned int index = 0u; index < BENCH_PAGE_COUNT; index++) {
        char name[40];
        const char *suffix = index == 0u ? "4k" : index == 1u ? "64k" : "1m";
        (void)snprintf(name, sizeof(name), "aes-ctr-128-%s", suffix);
        if (!bench_run_ctr_phase(out, &state, &summary, name, BENCH_CTR_KEY_128, sizeof(BENCH_CTR_KEY_128), BENCH_PAGE_SIZES[index], samples, warmup)) goto done;
        (void)snprintf(name, sizeof(name), "aes-ctr-256-%s", suffix);
        if (!bench_run_ctr_phase(out, &state, &summary, name, BENCH_CTR_KEY_256, sizeof(BENCH_CTR_KEY_256), BENCH_PAGE_SIZES[index], samples, warmup)) goto done;
    }
    for (unsigned int index = 0u; index < BENCH_PAGE_COUNT; index++) {
        char name[48];
        (void)snprintf(name, sizeof(name), "shell-payload-decode-%s", index == 0u ? "4k" : index == 1u ? "64k" : "1m");
        if (!bench_run_shell_phase(out, &state, &summary, name, &state.shell_payloads[index], samples, warmup)) goto done;
    }
    /* A standalone runner has no attached JVM or verified artifact/session.
     * Keep these phases explicit and fail-closed instead of treating a local
     * imitation as evidence for prepared or nested production execution. */
    bench_unsupported_phase_report(out, &summary, "vm-prepared-execution", "requires-live-jni-session");
    bench_unsupported_phase_report(out, &summary, "vm-nested-execution", "requires-live-jni-session");
    if (!bench_run_resource_index_phase(out, &state, &summary, "resource-alias-lookup", UINT64_C(0x616c696173), samples, warmup)) goto done;
    if (!bench_run_resource_index_phase(out, &state, &summary, "resource-commitment-lookup", UINT64_C(0x636f6d6d69746d65), samples, warmup)) goto done;
    if (!bench_run_jni_cache_phase(out, &state, &summary, "jni-method-class-lookup", samples, warmup)) goto done;
    if (!bench_run_zstd_context_phase(out, &state, &summary, "zstd-context-reuse", samples, warmup)) goto done;
    completed = 1;
    result_status = bench_result_status_for(&summary, baseline);

done:
    bench_summary_report(out, &state, &summary, baseline);
    if (!completed) {
        fprintf(out, "benchmark_result status=security-blocked reason=phase-execution-failed\n");
    } else {
        fprintf(out, "benchmark_result status=%s\n", bench_result_status_name(result_status));
    }
    bench_state_clear(&state);
    return completed && result_status == BENCH_RESULT_PASS;
}

int js_runtime_benchmark_run_with_security_baseline(
    FILE *out,
    unsigned int samples,
    unsigned int warmup,
    const js_crypto_runtime_metrics *minimum_security_counters,
    int has_differential_output_digest,
    uint64_t differential_output_digest
) {
    bench_security_baseline baseline;
    if (samples == 0u) samples = BENCH_DEFAULT_SAMPLES;
    bench_security_baseline_from_metrics(
        &baseline,
        minimum_security_counters,
        has_differential_output_digest,
        differential_output_digest);
    return bench_run_one(out, samples, warmup, &baseline);
}

int js_runtime_benchmark_run_with_warmup(FILE *out, unsigned int samples, unsigned int warmup) {
    if (samples == 0u) samples = BENCH_DEFAULT_SAMPLES;
    return bench_run_one(out, samples, warmup, NULL);
}

int js_runtime_benchmark_run(FILE *out, unsigned int samples) {
    return js_runtime_benchmark_run_with_warmup(out, samples, BENCH_DEFAULT_WARMUP);
}

static int bench_run_matrix(
    FILE *out,
    unsigned int warmup,
    const bench_security_baseline *baseline
) {
    int all_passed = 1;
    if (!out || warmup > BENCH_MAX_WARMUP) return 0;
    for (size_t index = 0u; index < sizeof(BENCH_STANDARD_SAMPLE_COUNTS) / sizeof(BENCH_STANDARD_SAMPLE_COUNTS[0]); index++) {
        fprintf(out, "matrix_profile samples=%u\n", BENCH_STANDARD_SAMPLE_COUNTS[index]);
        if (!bench_run_one(out, BENCH_STANDARD_SAMPLE_COUNTS[index], warmup, baseline)) all_passed = 0;
    }
    return all_passed;
}

int js_runtime_benchmark_run_matrix(FILE *out, unsigned int warmup) {
    return bench_run_matrix(out, warmup, NULL);
}

#if defined(JS_RUNTIME_BENCH_MAIN)
static int bench_parse_unsigned(const char *value, unsigned int *out) {
    char *end = NULL;
    unsigned long parsed;
    if (!value || !out || *value == '\0') return 0;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || end == value || *end != '\0' || parsed > UINT_MAX) return 0;
    *out = (unsigned int)parsed;
    return 1;
}

static void bench_print_usage(const char *program) {
    fprintf(stderr,
        "usage: %s [SAMPLES [WARMUP]] [--baseline FILE] [--differential-output-digest HEX]\n"
        "       %s --matrix [WARMUP] [--baseline FILE] [--differential-output-digest HEX]\n",
        program,
        program);
}

int main(int argc, char **argv) {
    unsigned int samples = BENCH_DEFAULT_SAMPLES;
    unsigned int warmup = BENCH_DEFAULT_WARMUP;
    unsigned int positional_count = 0u;
    uint64_t explicit_differential_output_digest = 0u;
    const char *baseline_path = NULL;
    bench_security_baseline baseline;
    const bench_security_baseline *baseline_ptr = NULL;
    int matrix = 0;
    int has_explicit_differential_output_digest = 0;
    memset(&baseline, 0, sizeof(baseline));
    for (int index = 1; index < argc; index++) {
        const char *argument = argv[index];
        if (strcmp(argument, "--help") == 0) {
            bench_print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argument, "--matrix") == 0) {
            if (matrix || positional_count != 0u) {
                bench_print_usage(argv[0]);
                return 2;
            }
            matrix = 1;
            continue;
        }
        if (strcmp(argument, "--baseline") == 0) {
            if (baseline_path || ++index >= argc) {
                bench_print_usage(argv[0]);
                return 2;
            }
            baseline_path = argv[index];
            continue;
        }
        if (strcmp(argument, "--differential-output-digest") == 0) {
            if (has_explicit_differential_output_digest || ++index >= argc ||
                !bench_parse_digest_u64(argv[index], &explicit_differential_output_digest)) {
                fprintf(stderr, "differential output digest must be exactly 16 hexadecimal characters\n");
                return 2;
            }
            has_explicit_differential_output_digest = 1;
            continue;
        }
        if (*argument == '-') {
            bench_print_usage(argv[0]);
            return 2;
        }
        if (matrix) {
            if (positional_count != 0u || !bench_parse_unsigned(argument, &warmup) || warmup > BENCH_MAX_WARMUP) {
                fprintf(stderr, "matrix warmup must be in 0..%u\n", BENCH_MAX_WARMUP);
                return 2;
            }
        } else if (positional_count == 0u) {
            if (!bench_parse_unsigned(argument, &samples) || samples == 0u || samples > BENCH_MAX_SAMPLES) {
                fprintf(stderr, "samples must be in 1..%u\n", BENCH_MAX_SAMPLES);
                return 2;
            }
        } else if (positional_count == 1u) {
            if (!bench_parse_unsigned(argument, &warmup) || warmup > BENCH_MAX_WARMUP) {
                fprintf(stderr, "warmup must be in 0..%u\n", BENCH_MAX_WARMUP);
                return 2;
            }
        } else {
            bench_print_usage(argv[0]);
            return 2;
        }
        ++positional_count;
    }
    if (baseline_path) {
        (void)bench_security_baseline_load(baseline_path, &baseline);
        baseline_ptr = &baseline;
        if (!baseline.valid) fprintf(stderr, "baseline security-counter record is invalid\n");
    }
    if (has_explicit_differential_output_digest) {
        if (!baseline_ptr) baseline_ptr = &baseline;
        baseline.has_differential_output_digest = 1u;
        baseline.differential_output_digest = explicit_differential_output_digest;
    }
    if (matrix) return bench_run_matrix(stdout, warmup, baseline_ptr) ? 0 : 1;
    return bench_run_one(stdout, samples, warmup, baseline_ptr) ? 0 : 1;
}
#endif
