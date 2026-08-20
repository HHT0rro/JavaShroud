/*
 * Native runtime-metrics atomicity probe.
 *
 * Link this source with js_crypto.c and define
 * JS_RUNTIME_METRICS_ATOMICITY_PROBE=1.  It deliberately uses only the public
 * metrics hooks/snapshot ABI so it verifies the same counter implementation
 * used by crypto, VM, resource, JNI, and loader hot paths.
 */
#include "js_crypto.h"

#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifndef JS_RUNTIME_METRICS_ATOMICITY_PROBE
#error "runtime_metrics_atomicity_probe.c requires JS_RUNTIME_METRICS_ATOMICITY_PROBE=1"
#endif

enum {
    JS_RUNTIME_METRICS_PROBE_THREADS = 8u,
    JS_RUNTIME_METRICS_PROBE_INCREMENTS_PER_THREAD = 250000u,
    JS_RUNTIME_METRICS_PROBE_SNAPSHOTS = 1024u
};

typedef struct {
    unsigned int increments;
} js_runtime_metrics_probe_worker;

static int js_runtime_metrics_probe_expect(int condition, const char *message) {
    if (condition) return 1;
    fprintf(stderr, "runtime metrics atomicity probe: %s\n", message);
    return 0;
}

static int js_runtime_metrics_probe_all_zero(const js_crypto_runtime_metrics *metrics) {
    if (!metrics) return 0;
    return metrics->hardware_crypto_path == 0u &&
        metrics->software_crypto_path == 0u &&
        metrics->aes_block_count == 0u &&
        metrics->ghash_block_count == 0u &&
        metrics->vm_frame_reuse_count == 0u &&
        metrics->vm_heap_fallback_count == 0u &&
        metrics->resource_index_hit_count == 0u &&
        metrics->decompress_context_reuse_count == 0u &&
        metrics->jni_cache_hit_count == 0u &&
        metrics->auth_check_count == 0u &&
        metrics->auth_failure_count == 0u &&
        metrics->digest_check_count == 0u &&
        metrics->tag_check_count == 0u &&
        metrics->length_check_count == 0u &&
        metrics->structure_check_count == 0u &&
        metrics->jni_abi_check_count == 0u &&
        metrics->wipe_count == 0u &&
        metrics->wipe_failure_count == 0u &&
        metrics->plaintext_persistence_bytes == 0u &&
        metrics->fallback_count == 0u &&
        metrics->legacy_path_hits == 0u &&
        metrics->exception_count == 0u &&
        metrics->security_checks_skipped == 0u &&
        metrics->phase_p50 == 0u &&
        metrics->phase_p95 == 0u &&
        metrics->phase_max == 0u;
}

static void js_runtime_metrics_probe_worker_run(js_runtime_metrics_probe_worker *worker) {
    if (!worker) return;
    for (unsigned int index = 0u; index < worker->increments; index++) {
        js_runtime_metrics_note_auth_check();
    }
}

#ifdef _WIN32
static DWORD WINAPI js_runtime_metrics_probe_worker_entry(LPVOID opaque) {
    js_runtime_metrics_probe_worker_run((js_runtime_metrics_probe_worker *)opaque);
    return 0u;
}
#else
static void *js_runtime_metrics_probe_worker_entry(void *opaque) {
    js_runtime_metrics_probe_worker_run((js_runtime_metrics_probe_worker *)opaque);
    return NULL;
}
#endif

int main(void) {
    js_runtime_metrics_probe_worker workers[JS_RUNTIME_METRICS_PROBE_THREADS];
    js_crypto_runtime_metrics metrics;
    uint64_t previous = 0u;
    uint64_t expected = (uint64_t)JS_RUNTIME_METRICS_PROBE_THREADS *
        (uint64_t)JS_RUNTIME_METRICS_PROBE_INCREMENTS_PER_THREAD;

    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&metrics);
    if (!js_runtime_metrics_probe_expect(
            js_runtime_metrics_probe_all_zero(&metrics),
            "reset did not atomically expose zeroed counters")) return 1;

    for (unsigned int index = 0u; index < JS_RUNTIME_METRICS_PROBE_THREADS; index++) {
        workers[index].increments = JS_RUNTIME_METRICS_PROBE_INCREMENTS_PER_THREAD;
    }

#ifdef _WIN32
    HANDLE threads[JS_RUNTIME_METRICS_PROBE_THREADS];
    for (unsigned int index = 0u; index < JS_RUNTIME_METRICS_PROBE_THREADS; index++) {
        threads[index] = CreateThread(NULL, 0u, js_runtime_metrics_probe_worker_entry, &workers[index], 0u, NULL);
        if (!js_runtime_metrics_probe_expect(threads[index] != NULL, "failed to create worker thread")) return 1;
    }
#else
    pthread_t threads[JS_RUNTIME_METRICS_PROBE_THREADS];
    for (unsigned int index = 0u; index < JS_RUNTIME_METRICS_PROBE_THREADS; index++) {
        if (!js_runtime_metrics_probe_expect(
                pthread_create(&threads[index], NULL, js_runtime_metrics_probe_worker_entry, &workers[index]) == 0,
                "failed to create worker thread")) return 1;
    }
#endif

    for (unsigned int index = 0u; index < JS_RUNTIME_METRICS_PROBE_SNAPSHOTS; index++) {
        js_crypto_runtime_metrics_snapshot(&metrics);
        if (!js_runtime_metrics_probe_expect(
                metrics.auth_check_count >= previous && metrics.auth_check_count <= expected,
                "concurrent snapshot observed a torn or non-monotonic counter")) return 1;
        previous = metrics.auth_check_count;
    }

#ifdef _WIN32
    if (!js_runtime_metrics_probe_expect(
            WaitForMultipleObjects(JS_RUNTIME_METRICS_PROBE_THREADS, threads, TRUE, INFINITE) == WAIT_OBJECT_0,
            "worker threads did not terminate")) return 1;
    for (unsigned int index = 0u; index < JS_RUNTIME_METRICS_PROBE_THREADS; index++) CloseHandle(threads[index]);
#else
    for (unsigned int index = 0u; index < JS_RUNTIME_METRICS_PROBE_THREADS; index++) {
        if (!js_runtime_metrics_probe_expect(pthread_join(threads[index], NULL) == 0, "worker thread did not join")) return 1;
    }
#endif

    js_crypto_runtime_metrics_snapshot(&metrics);
    if (!js_runtime_metrics_probe_expect(
            metrics.auth_check_count == expected,
            "concurrent increments lost or duplicated a metric update")) return 1;

    js_crypto_runtime_metrics_reset();
    js_crypto_runtime_metrics_snapshot(&metrics);
    if (!js_runtime_metrics_probe_expect(
            js_runtime_metrics_probe_all_zero(&metrics),
            "post-worker reset/snapshot did not expose a zeroed aggregate")) return 1;

    printf("runtime metrics atomicity probe: PASS threads=%u increments_per_thread=%u expected=%llu\n",
        JS_RUNTIME_METRICS_PROBE_THREADS,
        JS_RUNTIME_METRICS_PROBE_INCREMENTS_PER_THREAD,
        (unsigned long long)expected);
    return 0;
}
