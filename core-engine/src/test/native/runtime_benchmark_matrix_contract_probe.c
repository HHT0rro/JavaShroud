/*
 * Bounded contract probe for the native-runtime benchmark harness.
 *
 * The full native benchmark intentionally supports expensive 100, 1000,
 * 10000, and 100000 sample profiles.  Running all of them in a regular unit
 * test would turn a report-schema/security regression test into a multi-hour
 * throughput job.  This probe instead verifies the exact profile catalogue
 * and percentile ranks, then executes one measured sample after a nonzero
 * warmup through every available standalone phase.  It validates only
 * de-identified report fields and confirms that an unbound standalone run
 * remains fail-closed.
 */
#define JS_RUNTIME_BENCH_MAIN 1
#define main benchmark_matrix_contract_embedded_main
#include "native_runtime_benchmark.c"
#undef main
#undef JS_RUNTIME_BENCH_MAIN

#include <ctype.h>

#define PROBE_SAMPLES 1u
#define PROBE_WARMUP 3u

static const unsigned int PROBE_PROFILE_COUNTS[] = {100u, 1000u, 10000u, 100000u};
static const char *const PROBE_PHASES[] = {
    "aes-gcm-128-kat",
    "aes-gcm-256-kat",
    "ghash-aad-authenticated-page-4k",
    "ghash-aad-authenticated-page-64k",
    "ghash-aad-authenticated-page-1m",
    "aes-ctr-128-4k",
    "aes-ctr-256-4k",
    "aes-ctr-128-64k",
    "aes-ctr-256-64k",
    "aes-ctr-128-1m",
    "aes-ctr-256-1m",
    "shell-payload-decode-4k",
    "shell-payload-decode-64k",
    "shell-payload-decode-1m",
    "resource-alias-lookup",
    "resource-commitment-lookup",
    "jni-method-class-lookup"
};

static const char *const PROBE_UNSUPPORTED_PHASES[] = {
    "vm-prepared-execution",
    "vm-nested-execution",
    "zstd-context-reuse"
};

static int probe_fail(const char *reason) {
    fprintf(stderr, "benchmark_matrix_contract_probe failure=%s\n", reason ? reason : "unknown");
    return 0;
}

static int probe_line_starts_with(const char *line, const char *prefix) {
    size_t prefix_size;
    if (!line || !prefix) return 0;
    prefix_size = strlen(prefix);
    return strncmp(line, prefix, prefix_size) == 0;
}

static const char *probe_find_line(const char *text, const char *prefix) {
    const char *line = text;
    if (!text || !prefix) return NULL;
    while (*line) {
        if (probe_line_starts_with(line, prefix)) return line;
        line = strchr(line, '\n');
        if (!line) break;
        ++line;
    }
    return NULL;
}

static size_t probe_count_lines(const char *text, const char *prefix) {
    const char *line = text;
    size_t count = 0u;
    if (!text || !prefix) return 0u;
    while (*line) {
        if (probe_line_starts_with(line, prefix)) ++count;
        line = strchr(line, '\n');
        if (!line) break;
        ++line;
    }
    return count;
}

static int probe_field_span(
    const char *line,
    const char *name,
    const char **value,
    size_t *value_size
) {
    const char *cursor;
    size_t name_size;
    if (!line || !name || !value || !value_size) return 0;
    name_size = strlen(name);
    cursor = line;
    while (*cursor && *cursor != '\n') {
        const char *token = cursor;
        const char *end;
        while (*cursor && *cursor != ' ' && *cursor != '\n') ++cursor;
        end = cursor;
        if ((size_t)(end - token) > name_size && strncmp(token, name, name_size) == 0 && token[name_size] == '=') {
            *value = token + name_size + 1u;
            *value_size = (size_t)(end - *value);
            return 1;
        }
        while (*cursor == ' ') ++cursor;
    }
    return 0;
}

static int probe_field_equals(const char *line, const char *name, const char *expected) {
    const char *value;
    size_t value_size;
    size_t expected_size;
    if (!expected || !probe_field_span(line, name, &value, &value_size)) return 0;
    expected_size = strlen(expected);
    return value_size == expected_size && memcmp(value, expected, value_size) == 0;
}

static int probe_field_u64(const char *line, const char *name, uint64_t *out) {
    const char *value;
    size_t value_size;
    char buffer[32];
    char *end = NULL;
    unsigned long long parsed;
    if (!out || !probe_field_span(line, name, &value, &value_size) || value_size == 0u || value_size >= sizeof(buffer)) return 0;
    memcpy(buffer, value, value_size);
    buffer[value_size] = '\0';
    errno = 0;
    parsed = strtoull(buffer, &end, 10);
    if (errno != 0 || !end || *end != '\0') return 0;
    *out = (uint64_t)parsed;
    return 1;
}

static int probe_field_hex16(const char *line, const char *name, uint64_t *out) {
    const char *value;
    size_t value_size;
    char buffer[17];
    char *end = NULL;
    unsigned long long parsed;
    if (!out || !probe_field_span(line, name, &value, &value_size) || value_size != 16u) return 0;
    for (size_t index = 0u; index < value_size; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    }
    memcpy(buffer, value, value_size);
    buffer[value_size] = '\0';
    errno = 0;
    parsed = strtoull(buffer, &end, 16);
    if (errno != 0 || !end || *end != '\0') return 0;
    *out = (uint64_t)parsed;
    return 1;
}

static int probe_zero_field(const char *line, const char *name) {
    uint64_t value;
    return probe_field_u64(line, name, &value) && value == 0u;
}

static int probe_authenticated_phase(const char *name) {
    return strncmp(name, "aes-gcm-", 8u) == 0 ||
        strncmp(name, "ghash-aad-authenticated-page-", 29u) == 0 ||
        strncmp(name, "shell-payload-decode-", 21u) == 0;
}

static int probe_validate_matrix_cli_contract(void) {
    char matrix_duplicate_program[] = "benchmark";
    char matrix_duplicate_flag[] = "--matrix";
    char matrix_duplicate_arguments[] = "--matrix";
    char matrix_warmup_program[] = "benchmark";
    char matrix_warmup_flag[] = "--matrix";
    char matrix_warmup_value[] = "100001";
    char *duplicate_argv[] = {
        matrix_duplicate_program,
        matrix_duplicate_flag,
        matrix_duplicate_arguments
    };
    char *warmup_argv[] = {
        matrix_warmup_program,
        matrix_warmup_flag,
        matrix_warmup_value
    };
    /* These bounded invalid invocations exercise the same CLI parser that
     * dispatches --matrix, without accidentally launching the expensive
     * 100000-sample profile during a regular test run. */
    if (benchmark_matrix_contract_embedded_main(3, duplicate_argv) != 2) return probe_fail("matrix-cli-duplicate");
    if (benchmark_matrix_contract_embedded_main(3, warmup_argv) != 2) return probe_fail("matrix-cli-warmup-limit");
    return 1;
}

static int probe_validate_profile_contract(void) {
    static const size_t expected_p50[] = {49u, 499u, 4999u, 49999u};
    static const size_t expected_p95[] = {94u, 949u, 9499u, 94999u};
    static const size_t expected_p99[] = {98u, 989u, 9899u, 98999u};
    const size_t count = sizeof(PROBE_PROFILE_COUNTS) / sizeof(PROBE_PROFILE_COUNTS[0]);
    if (sizeof(BENCH_STANDARD_SAMPLE_COUNTS) / sizeof(BENCH_STANDARD_SAMPLE_COUNTS[0]) != count) return probe_fail("profile-count");
    if (BENCH_MAX_SAMPLES != PROBE_PROFILE_COUNTS[count - 1u]) return probe_fail("profile-limit");
    for (size_t index = 0u; index < count; ++index) {
        unsigned int samples = PROBE_PROFILE_COUNTS[index];
        if (BENCH_STANDARD_SAMPLE_COUNTS[index] != samples) return probe_fail("profile-value");
        if (bench_percentile_index(samples, 500u) != expected_p50[index]) return probe_fail("p50-rank");
        if (bench_percentile_index(samples, 950u) != expected_p95[index]) return probe_fail("p95-rank");
        if (bench_percentile_index(samples, 990u) != expected_p99[index]) return probe_fail("p99-rank");
        if (bench_percentile_index(samples, 1000u) != (size_t)samples - 1u) return probe_fail("max-rank");
    }
    return 1;
}

static int probe_validate_phase(const char *report, const char *name) {
    static const char *const required_fields[] = {
        "p50", "p95", "p99", "max", "output_digest",
        "allocation_count", "allocation_bytes", "exception_count", "native_exception_count",
        "hardware_crypto_path", "software_crypto_path", "aes_block_count", "ghash_block_count",
        "auth_check_count", "auth_failure_count", "digest_check_count", "tag_check_count",
        "length_check_count", "structure_check_count", "jni_abi_check_count", "wipe_count",
        "wipe_failure_count", "plaintext_persistence_bytes", "fallback_count", "legacy_path_hits",
        "security_checks_skipped"
    };
    char prefix[96];
    const char *line;
    uint64_t p50, p95, p99, maximum, digest;
    (void)snprintf(prefix, sizeof(prefix), "phase=%s ", name);
    if (probe_count_lines(report, prefix) != 1u) return probe_fail("phase-count");
    line = probe_find_line(report, prefix);
    if (!line ||
        !probe_field_equals(line, "phase_status", "pass") ||
        !probe_field_equals(line, "timing_unit", "ns") ||
        !probe_field_equals(line, "percentile", "nearest-rank") ||
        !probe_field_equals(line, "samples", "1") ||
        !probe_field_equals(line, "warmup", "3") ||
        !probe_field_equals(line, "warmup_excluded", "1")) return probe_fail("phase-header");
    for (size_t index = 0u; index < sizeof(required_fields) / sizeof(required_fields[0]); ++index) {
        const char *value;
        size_t value_size;
        if (!probe_field_span(line, required_fields[index], &value, &value_size) || value_size == 0u) return probe_fail("phase-field");
    }
    if (!probe_field_u64(line, "p50", &p50) ||
        !probe_field_u64(line, "p95", &p95) ||
        !probe_field_u64(line, "p99", &p99) ||
        !probe_field_u64(line, "max", &maximum) ||
        p50 > p95 || p95 > p99 || p99 > maximum ||
        !probe_field_hex16(line, "output_digest", &digest)) return probe_fail("phase-latency-or-digest");
    if (!probe_zero_field(line, "allocation_count") ||
        !probe_zero_field(line, "allocation_bytes") ||
        !probe_zero_field(line, "exception_count") ||
        !probe_zero_field(line, "native_exception_count") ||
        !probe_zero_field(line, "auth_failure_count") ||
        !probe_zero_field(line, "wipe_failure_count") ||
        !probe_zero_field(line, "plaintext_persistence_bytes") ||
        !probe_zero_field(line, "fallback_count") ||
        !probe_zero_field(line, "legacy_path_hits") ||
        !probe_zero_field(line, "security_checks_skipped")) return probe_fail("phase-security-counter");
    if (probe_authenticated_phase(name)) {
        uint64_t auth, tag, length, structure, wipes;
        if (!probe_field_u64(line, "auth_check_count", &auth) || auth == 0u ||
            !probe_field_u64(line, "tag_check_count", &tag) || tag == 0u ||
            !probe_field_u64(line, "length_check_count", &length) || length == 0u ||
            !probe_field_u64(line, "structure_check_count", &structure) || structure == 0u ||
            !probe_field_u64(line, "wipe_count", &wipes) || wipes == 0u) return probe_fail("authenticated-phase-counter");
    }
    return 1;
}

static int probe_validate_unsupported_phase(const char *report, const char *name) {
    char prefix[96];
    const char *line;
    (void)snprintf(prefix, sizeof(prefix), "phase=%s ", name);
    if (probe_count_lines(report, prefix) != 1u) return probe_fail("unsupported-count");
    line = probe_find_line(report, prefix);
    if (!line ||
        !probe_field_equals(line, "phase_mode", "integration-adapter") ||
        !probe_field_equals(line, "phase_status", "unsupported") ||
        !probe_field_equals(line, "security_gate", "not-applicable")) return probe_fail("unsupported-header");
    {
        uint64_t digest;
        if (!probe_field_hex16(line, "output_digest", &digest)) return probe_fail("unsupported-digest");
    }
    return 1;
}

static int probe_capture_report(char **out_report, size_t *out_size) {
    FILE *file;
    long size;
    char *report;
    int run_result;
    if (!out_report || !out_size) return 0;
    *out_report = NULL;
    *out_size = 0u;
    file = tmpfile();
    if (!file) return 0;
    run_result = bench_run_one(file, PROBE_SAMPLES, PROBE_WARMUP, NULL);
    if (run_result != 0) {
        fclose(file);
        return 0;
    }
    if (fflush(file) != 0 || fseek(file, 0L, SEEK_END) != 0 || (size = ftell(file)) <= 0L ||
        fseek(file, 0L, SEEK_SET) != 0 || size > 16L * 1024L * 1024L) {
        fclose(file);
        return 0;
    }
    report = (char *)malloc((size_t)size + 1u);
    if (!report) {
        fclose(file);
        return 0;
    }
    if (fread(report, 1u, (size_t)size, file) != (size_t)size) {
        bench_secure_zero(report, (size_t)size + 1u);
        free(report);
        fclose(file);
        return 0;
    }
    report[size] = '\0';
    fclose(file);
    *out_report = report;
    *out_size = (size_t)size;
    return 1;
}

static int probe_validate_report(const char *report, uint64_t *out_digest, uint64_t *out_hardware_path, uint64_t *out_software_path) {
    const char *suite;
    const char *capability;
    const char *metrics;
    const char *baseline;
    const char *coverage;
    const char *security;
    const char *candidate;
    const char *result;
    uint64_t hardware_aes, hardware_ghash, output_digest, hardware_path, software_path;
    if (!report || !out_digest || !out_hardware_path || !out_software_path) return 0;
    suite = probe_find_line(report, "suite=native-runtime-benchmark ");
    capability = probe_find_line(report, "capability ");
    metrics = probe_find_line(report, "metrics ");
    baseline = probe_find_line(report, "baseline_security ");
    coverage = probe_find_line(report, "coverage_gate ");
    security = probe_find_line(report, "security_gate ");
    candidate = probe_find_line(report, "benchmark_gate_candidate ");
    result = probe_find_line(report, "benchmark_result ");
    if (!suite || !capability || !metrics || !baseline || !coverage || !security || !candidate || !result) return probe_fail("report-line");
    if (!probe_field_equals(suite, "schema", "3") ||
        !probe_field_equals(suite, "samples", "1") ||
        !probe_field_equals(suite, "warmup", "3") ||
        !probe_field_equals(suite, "sample_profiles", "100,1000,10000,100000")) return probe_fail("suite-contract");
    if (!probe_field_u64(capability, "hardware_aes", &hardware_aes) || hardware_aes > 1u ||
        !probe_field_u64(capability, "hardware_ghash", &hardware_ghash) || hardware_ghash > 1u) return probe_fail("capability-contract");
    for (size_t index = 0u; index < sizeof(PROBE_PHASES) / sizeof(PROBE_PHASES[0]); ++index) {
        if (!probe_validate_phase(report, PROBE_PHASES[index])) return 0;
    }
    for (size_t index = 0u; index < sizeof(PROBE_UNSUPPORTED_PHASES) / sizeof(PROBE_UNSUPPORTED_PHASES[0]); ++index) {
        if (!probe_validate_unsupported_phase(report, PROBE_UNSUPPORTED_PHASES[index])) return 0;
    }
    if (!probe_field_u64(metrics, "hardware_crypto_path", &hardware_path) ||
        !probe_field_u64(metrics, "software_crypto_path", &software_path) ||
        !probe_field_hex16(metrics, "output_digest", &output_digest) ||
        !probe_field_equals(metrics, "unsupported_phase_count", "3") ||
        !probe_field_equals(metrics, "required_production_nonproduction_phase_count", "12")) return probe_fail("metrics-contract");
    if (!probe_zero_field(metrics, "auth_failure_count") ||
        !probe_zero_field(metrics, "wipe_failure_count") ||
        !probe_zero_field(metrics, "plaintext_persistence_bytes") ||
        !probe_zero_field(metrics, "fallback_count") ||
        !probe_zero_field(metrics, "legacy_path_hits") ||
        !probe_zero_field(metrics, "exception_count") ||
        !probe_zero_field(metrics, "security_checks_skipped")) return probe_fail("metrics-security-counter");
    if (!probe_field_equals(baseline, "status", "missing") ||
        !probe_field_equals(coverage, "status", "coverage-incomplete") ||
        !probe_field_equals(security, "status", "security-blocked") ||
        !probe_field_equals(security, "reason", "baseline-missing") ||
        !probe_field_equals(candidate, "status", "security-blocked") ||
        !probe_field_equals(result, "status", "security-blocked")) return probe_fail("fail-closed-gate");
    *out_digest = output_digest;
    *out_hardware_path = hardware_path;
    *out_software_path = software_path;
    return 1;
}

int main(void) {
    char *report = NULL;
    size_t report_size = 0u;
    uint64_t output_digest = 0u;
    uint64_t hardware_path = 0u;
    uint64_t software_path = 0u;
    if (!probe_validate_profile_contract()) return 2;
    if (!probe_validate_matrix_cli_contract()) return 2;
    if (!probe_capture_report(&report, &report_size)) {
        (void)probe_fail("capture-report");
        return 3;
    }
    if (!probe_validate_report(report, &output_digest, &hardware_path, &software_path)) {
        bench_secure_zero(report, report_size);
        free(report);
        return 4;
    }
    if (fwrite(report, 1u, report_size, stdout) != report_size) {
        bench_secure_zero(report, report_size);
        free(report);
        return 5;
    }
    printf(
        "matrix_contract status=pass profiles=100,1000,10000,100000 warmup=%u measured_samples=%u "
        "phase_count=%u unsupported_phase_count=%u hardware_aes=%d hardware_ghash=%d "
        "hardware_crypto_path=%llu software_crypto_path=%llu output_digest=%016llx\n",
        PROBE_WARMUP,
        PROBE_SAMPLES,
        (unsigned int)(sizeof(PROBE_PHASES) / sizeof(PROBE_PHASES[0])),
        (unsigned int)(sizeof(PROBE_UNSUPPORTED_PHASES) / sizeof(PROBE_UNSUPPORTED_PHASES[0])),
        js_aes_hardware_available(),
        js_ghash_hardware_available(),
        (unsigned long long)hardware_path,
        (unsigned long long)software_path,
        (unsigned long long)output_digest);
    bench_secure_zero(report, report_size);
    free(report);
    return 0;
}
