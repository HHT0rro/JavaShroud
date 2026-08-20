/*
 * Native benchmark gate probe.
 *
 * It includes the fixture implementation so the status reducer and strict
 * baseline parser are exercised without running a long 1 MiB benchmark.  The
 * probe never uses or prints keys, nonces, plaintext, paths, or exceptions.
 */
#include "native_runtime_benchmark.c"

static int probe_expect(bench_result_status actual, bench_result_status expected) {
    return actual == expected ? 1 : 0;
}

int main(int argc, char **argv) {
    bench_security_baseline baseline;
    bench_summary summary;
    if (argc != 2 || !bench_security_baseline_load(argv[1], &baseline) || !baseline.valid) return 2;
    memset(&summary, 0, sizeof(summary));
    summary.metrics = baseline.minimum;
    summary.output_digest = baseline.differential_output_digest;

    /* A complete, baseline-bound, software-reference candidate is accepted. */
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_PASS)) return 3;

    /* Synthetic or unsupported required production phases cannot close the gate. */
    summary.synthetic_phase_count = 1u;
    summary.required_production_nonproduction_phase_count = 1u;
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_COVERAGE_INCOMPLETE)) return 4;
    summary.synthetic_phase_count = 0u;
    summary.unsupported_phase_count = 1u;
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_COVERAGE_INCOMPLETE)) return 5;
    summary.unsupported_phase_count = 0u;
    summary.required_production_nonproduction_phase_count = 0u;

    /* A counter below the fixed floor is security-blocked. */
    summary.metrics.auth_check_count = baseline.minimum.auth_check_count - 1u;
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_SECURITY_BLOCKED)) return 6;
    summary.metrics.auth_check_count = baseline.minimum.auth_check_count;

    /* Forbidden fallback activity is security-blocked even with good floors. */
    summary.metrics.fallback_count = 1u;
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_SECURITY_BLOCKED)) return 7;
    summary.metrics.fallback_count = 0u;

    /* Hardware dispatch requires a same-profile software differential digest. */
    baseline.has_differential_output_digest = 0u;
    summary.metrics.hardware_crypto_path = 1u;
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_SECURITY_BLOCKED)) return 8;
    baseline.has_differential_output_digest = 1u;
    summary.metrics.hardware_crypto_path = 0u;
    summary.output_digest ^= UINT64_C(1);
    if (!probe_expect(bench_result_status_for(&summary, &baseline), BENCH_RESULT_SECURITY_BLOCKED)) return 9;

    printf("benchmark_gate_probe status=pass coverage_incomplete=1 security_blocked=1 differential_blocked=1\n");
    return 0;
}
