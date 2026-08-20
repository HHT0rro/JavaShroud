#ifndef JS_RUNTIME_METRICS_H
#define JS_RUNTIME_METRICS_H

#include "js_crypto.h"

/* Counter-only, de-identified runtime telemetry.  The aliases keep the
 * snapshot ABI small while making phase ownership explicit to benchmark
 * fixtures and native callers.  The producer synchronizes individual counter
 * reads/writes; callers that need a phase boundary quiesce writers before
 * resetting or snapshotting the aggregate. */
typedef js_crypto_runtime_metrics NativeRuntimeMetrics;
typedef js_crypto_runtime_metrics CryptoRuntimeMetrics;
typedef js_crypto_runtime_metrics VmRuntimeMetrics;
typedef js_crypto_runtime_metrics ResourceRuntimeMetrics;
typedef js_crypto_runtime_metrics RuntimeSecurityCounters;

#endif
