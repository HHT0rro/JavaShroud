/*
 * Focused production-resource benchmark probe.
 *
 * This is intentionally separate from the crypto/shell-only runner.  It
 * enables JS_RUNTIME_BENCH_RESOURCE_RUNTIME and links the complete native
 * runtime source set, so the two resource phases call js_vm_resource.c's
 * immutable alias and JSRP commitment paths rather than the bounded synthetic
 * hash table.  The probe reports only the benchmark's de-identified counters
 * and phase digests.
 */
#define JS_RUNTIME_BENCH_RESOURCE_RUNTIME 1
#include "native_runtime_benchmark.c"

static int probe_build_artifact_fixture(bench_production_resource_fixture *fixture, unsigned int variant) {
    unsigned char digest[32];
    char digest_text[65];
    int manifest_len;
    if (!fixture || variant > 16u) return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->raw_len = 64u;
    fixture->partition_id = variant;
    (void)snprintf(
        fixture->path,
        sizeof(fixture->path),
        "META-INF/.bench/artifact-%u/resource.jsrp",
        variant);
    (void)snprintf(
        fixture->alias,
        sizeof(fixture->alias),
        "META-INF/.bench/artifact-%u/resource.alias",
        variant);
    for (size_t index = 0u; index < fixture->raw_len; index++) {
        fixture->raw[index] = (unsigned char)bench_mix(
            UINT64_C(0x736a72702d62656e) ^ ((uint64_t)variant << 32u) ^ index);
    }
    fixture->raw[0] = 'J';
    fixture->raw[1] = 'S';
    fixture->raw[2] = 'R';
    fixture->raw[3] = 'P';
    fixture->raw[4] = 7u;
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
    return 1;
}

static int probe_parse_unsigned(const char *text, unsigned int *out) {
    char *end = NULL;
    unsigned long parsed;
    if (!text || !out || *text == '\0') return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0' || parsed > UINT_MAX) return 0;
    *out = (unsigned int)parsed;
    return 1;
}

/*
 * Verify that the production alias/commitment indexes are generation scoped.
 * A reset must retire both the old route and the old JSRP commitment before a
 * replacement session can be installed; the check intentionally observes
 * only booleans, generation values, and de-identified counters.
 */
static int probe_run_resource_cache_generation(FILE *out) {
    bench_production_resource_fixture fixture;
    bench_production_resource_fixture artifact_a;
    bench_production_resource_fixture artifact_b;
    js_crypto_runtime_metrics metrics;
    char resolved[JS_VM_CALL_GATE_KEY_LEN];
    unsigned int generation_before = 0u;
    unsigned int generation_installed = 0u;
    unsigned int generation_after_reset = 0u;
    unsigned int generation_reinstalled = 0u;
    unsigned long long stale_index_hits = 0u;
    unsigned long long replacement_index_hits = 0u;
    int installed_alias = 0;
    int installed_commitment = 0;
    int stale_alias_reused = 1;
    int stale_alias_identity_resolution = 0;
    int stale_commitment_reused = 1;
    int replacement_alias = 0;
    int replacement_commitment = 0;
    int cross_artifact_a_match = 0;
    int cross_artifact_b_match = 0;
    int cross_artifact_swap_rejected = 0;
    int cross_artifact_alias_collision_rejected = 0;
    int duplicate_commitment_path_rejected = 0;
    int ok = 0;

    if (!out) return 0;
    memset(&fixture, 0, sizeof(fixture));
    memset(&artifact_a, 0, sizeof(artifact_a));
    memset(&artifact_b, 0, sizeof(artifact_b));
    memset(&metrics, 0, sizeof(metrics));
    memset(resolved, 0, sizeof(resolved));

    /* Install two current-format artifact entries in one authenticated index,
     * then prove that raw bytes cannot be replayed across their path bindings.
     * Only booleans and counters are reported; fixture bytes are wiped below. */
    js_vm_call_gate_reset();
    if (!probe_build_artifact_fixture(&artifact_a, 0u) ||
        !probe_build_artifact_fixture(&artifact_b, 1u)) goto cleanup;
    {
        char duplicate_manifest[sizeof(artifact_a.manifest) * 2u];
        char combined_manifest[sizeof(artifact_a.manifest) + sizeof(artifact_b.manifest)];
        int duplicate_len = snprintf(
            duplicate_manifest,
            sizeof(duplicate_manifest),
            "%s%s",
            artifact_a.manifest,
            artifact_a.manifest);
        int combined_len = snprintf(
            combined_manifest,
            sizeof(combined_manifest),
            "%s%s",
            artifact_a.manifest,
            artifact_b.manifest);
        duplicate_commitment_path_rejected =
            duplicate_len > 0 &&
            (size_t)duplicate_len < sizeof(duplicate_manifest) &&
            !js_vm_commitments_install((const unsigned char *)duplicate_manifest, duplicate_len);
        if (combined_len <= 0 || (size_t)combined_len >= sizeof(combined_manifest) ||
            !js_vm_commitments_install((const unsigned char *)combined_manifest, combined_len) ||
            !js_vm_resource_alias_register(artifact_a.alias, artifact_a.path) ||
            !js_vm_resource_alias_register(artifact_b.alias, artifact_b.path)) {
            bench_secure_zero(duplicate_manifest, sizeof(duplicate_manifest));
            bench_secure_zero(combined_manifest, sizeof(combined_manifest));
            goto cleanup;
        }
        cross_artifact_a_match = js_vm_commitment_matches(
            artifact_a.path, artifact_a.raw, (int)artifact_a.raw_len);
        cross_artifact_b_match = js_vm_commitment_matches(
            artifact_b.path, artifact_b.raw, (int)artifact_b.raw_len);
        cross_artifact_swap_rejected =
            !js_vm_commitment_matches(artifact_a.path, artifact_b.raw, (int)artifact_b.raw_len) &&
            !js_vm_commitment_matches(artifact_b.path, artifact_a.raw, (int)artifact_a.raw_len);
        cross_artifact_alias_collision_rejected =
            !js_vm_resource_alias_register("META-INF/.bench/collision.alias", artifact_a.path) &&
            !js_vm_resource_alias_register(artifact_a.alias, artifact_b.path);
        bench_secure_zero(duplicate_manifest, sizeof(duplicate_manifest));
        bench_secure_zero(combined_manifest, sizeof(combined_manifest));
    }

    js_vm_call_gate_reset();
    generation_before = js_vm_resource_session_generation_current();
    if (!bench_production_resource_fixture_prepare(&fixture)) goto cleanup;
    generation_installed = js_vm_resource_session_generation_current();

    installed_alias =
        js_vm_resource_alias_resolve_copy(fixture.alias, resolved, sizeof(resolved)) &&
        strcmp(resolved, fixture.path) == 0;
    memset(resolved, 0, sizeof(resolved));
    installed_commitment = js_vm_commitment_matches(
        fixture.path,
        fixture.raw,
        (int)fixture.raw_len);

    /* Retire the session and prove that the old alias and commitment cannot be
     * replayed through the cleared immutable indexes. */
    js_vm_call_gate_reset();
    generation_after_reset = js_vm_resource_session_generation_current();
    js_crypto_runtime_metrics_reset();
    stale_alias_identity_resolution =
        js_vm_resource_alias_resolve_copy(fixture.alias, resolved, sizeof(resolved)) &&
        strcmp(resolved, fixture.alias) == 0;
    stale_alias_reused =
        js_vm_resource_alias_resolve_copy(fixture.alias, resolved, sizeof(resolved)) &&
        strcmp(resolved, fixture.path) == 0;
    stale_commitment_reused = js_vm_commitment_matches(
        fixture.path,
        fixture.raw,
        (int)fixture.raw_len);
    js_crypto_runtime_metrics_snapshot(&metrics);
    stale_index_hits = (unsigned long long)metrics.resource_index_hit_count;

    /* Reinstall a fresh current session and require both indexes to resolve
     * only after the new generation has been authenticated and installed. */
    if (!bench_production_resource_fixture_prepare(&fixture)) goto cleanup;
    generation_reinstalled = js_vm_resource_session_generation_current();
    memset(resolved, 0, sizeof(resolved));
    js_crypto_runtime_metrics_reset();
    replacement_alias =
        js_vm_resource_alias_resolve_copy(fixture.alias, resolved, sizeof(resolved)) &&
        strcmp(resolved, fixture.path) == 0;
    replacement_commitment = js_vm_commitment_matches(
        fixture.path,
        fixture.raw,
        (int)fixture.raw_len);
    js_crypto_runtime_metrics_snapshot(&metrics);
    replacement_index_hits = (unsigned long long)metrics.resource_index_hit_count;

    ok = generation_installed != generation_after_reset &&
        generation_reinstalled != generation_after_reset &&
        installed_alias && installed_commitment &&
        !stale_alias_reused && stale_alias_identity_resolution &&
        !stale_commitment_reused && stale_index_hits == 0u &&
        replacement_alias && replacement_commitment && replacement_index_hits >= 2u &&
        cross_artifact_a_match && cross_artifact_b_match && cross_artifact_swap_rejected &&
        cross_artifact_alias_collision_rejected && duplicate_commitment_path_rejected &&
        metrics.fallback_count == 0u && metrics.legacy_path_hits == 0u &&
        metrics.wipe_failure_count == 0u && metrics.plaintext_persistence_bytes == 0u &&
        metrics.security_checks_skipped == 0u && metrics.exception_count == 0u;
    fprintf(
        out,
        "resource_cache_lifecycle phase_name=resource-cache-generation phase_mode=production status=%s "
        "generation_before=%u generation_installed=%u generation_after_reset=%u generation_reinstalled=%u "
        "stale_alias_reused=%d stale_alias_identity_resolution=%d stale_commitment_reused=%d "
        "stale_resource_index_hit_count=%llu replacement_resource_index_hit_count=%llu "
        "replacement_structure_check_count=%llu replacement_length_check_count=%llu replacement_digest_check_count=%llu "
        "cross_artifact_a_match=%d cross_artifact_b_match=%d cross_artifact_swap_rejected=%d "
        "cross_artifact_alias_collision_rejected=%d duplicate_commitment_path_rejected=%d "
        "fallback_count=%llu legacy_path_hits=%llu wipe_failure_count=%llu plaintext_persistence_bytes=%llu "
        "security_checks_skipped=%llu exception_count=%llu\n",
        ok ? "pass" : "fail",
        generation_before,
        generation_installed,
        generation_after_reset,
        generation_reinstalled,
        stale_alias_reused,
        stale_alias_identity_resolution,
        stale_commitment_reused,
        stale_index_hits,
        replacement_index_hits,
        (unsigned long long)metrics.structure_check_count,
        (unsigned long long)metrics.length_check_count,
        (unsigned long long)metrics.digest_check_count,
        cross_artifact_a_match,
        cross_artifact_b_match,
        cross_artifact_swap_rejected,
        cross_artifact_alias_collision_rejected,
        duplicate_commitment_path_rejected,
        (unsigned long long)metrics.fallback_count,
        (unsigned long long)metrics.legacy_path_hits,
        (unsigned long long)metrics.wipe_failure_count,
        (unsigned long long)metrics.plaintext_persistence_bytes,
        (unsigned long long)metrics.security_checks_skipped,
        (unsigned long long)metrics.exception_count);

cleanup:
    js_vm_call_gate_reset();
    bench_secure_zero(resolved, sizeof(resolved));
    bench_secure_zero(&fixture, sizeof(fixture));
    bench_secure_zero(&artifact_a, sizeof(artifact_a));
    bench_secure_zero(&artifact_b, sizeof(artifact_b));
    return ok;
}

int main(int argc, char **argv) {
    bench_state state;
    bench_summary summary;
    int alias_ok;
    int commitment_ok;
    int zstd_ok;
    int lifecycle_ok;
    unsigned int samples = 100u;
    unsigned int warmup = 16u;

    if (argc > 3 ||
        (argc >= 2 && !probe_parse_unsigned(argv[1], &samples)) ||
        (argc >= 3 && !probe_parse_unsigned(argv[2], &warmup)) ||
        samples == 0u || samples > BENCH_MAX_SAMPLES || warmup > BENCH_MAX_WARMUP) {
        fprintf(stderr, "usage: %s [samples [warmup]]\n", argc > 0 && argv[0] ? argv[0] : "runtime_resource_production_benchmark_probe");
        return 2;
    }

    memset(&state, 0, sizeof(state));
    memset(&summary, 0, sizeof(summary));
    if (!bench_state_init(&state, samples)) return 3;
    alias_ok = bench_run_resource_index_phase(
        stdout,
        &state,
        &summary,
        "resource-alias-lookup",
        UINT64_C(0x616c696173),
        samples,
        warmup);
    commitment_ok = bench_run_resource_index_phase(
        stdout,
        &state,
        &summary,
        "resource-commitment-lookup",
        UINT64_C(0x636f6d6d69746d65),
        samples,
        warmup);
    zstd_ok = bench_run_zstd_context_phase(
        stdout,
        &state,
        &summary,
        "zstd-context-reuse",
        samples,
        warmup);
    lifecycle_ok = probe_run_resource_cache_generation(stdout);
    bench_state_clear(&state);
    return alias_ok && commitment_ok && zstd_ok && lifecycle_ok ? 0 : 1;
}
