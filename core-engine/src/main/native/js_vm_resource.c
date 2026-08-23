#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "js_vm_resource.h"
#include "js_crypto.h"
#include "js_jni_runtime.h"
#include "js_vm_core.h"
#include "js_vm_symbol.h"
#include "native_secrets.inc"
#ifndef ZSTD_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#endif
#include "zstd.h"

#include <limits.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#endif

#define JS_VM_CALL_GATE_SIZE 8192
#define JS_VM_PRELOAD_WAIT_ATTEMPTS 10000
#define JS_VM_AKEN_PREPARED_CACHE_CAPACITY 128u
/* Resource aliases and commitments are installed once per artifact/session.
 * Keep the lookup tables bounded and power-of-two sized so the hot path uses
 * open addressing instead of scanning the full registration arrays. */
#define JS_VM_RESOURCE_INDEX_SIZE 16384u

#if defined(JS_AKEN_TYPED_ONLY_RUNTIME) && JS_AKEN_TYPED_ONLY_RUNTIME
/*
 * New AKEN output no longer uses the legacy VBC4 sliced-manifest protocol.
 * Keep the compatibility parser fail-closed without materializing its fixed
 * magic in the native image: static artifact scans must not find a reusable
 * `VBC4S|1|` protocol marker in an AKEN v4 direct kernel.
 */
static int js_aken_legacy_manifest_prefix_matches(const unsigned char *bytes, size_t length) {
    return bytes != NULL && length >= 8u &&
        bytes[0] == (unsigned char)'V' && bytes[1] == (unsigned char)'B' &&
        bytes[2] == (unsigned char)'C' && bytes[3] == (unsigned char)'4' &&
        bytes[4] == (unsigned char)'S' && bytes[5] == (unsigned char)'|' &&
        bytes[6] == (unsigned char)'1' && bytes[7] == (unsigned char)'|';
}

static int js_aken_legacy_manifest_header_matches(const char *magic, const char *version) {
    return magic != NULL && version != NULL &&
        magic[0] == 'V' && magic[1] == 'B' && magic[2] == 'C' &&
        magic[3] == '4' && magic[4] == 'S' && magic[5] == 0 &&
        version[0] == '1' && version[1] == 0;
}
#else
#ifndef JS_VBC4_MANIFEST_MAGIC
#define JS_VBC4_MANIFEST_MAGIC "VBC4S"
#endif
#ifndef JS_VBC4_MANIFEST_VERSION
#define JS_VBC4_MANIFEST_VERSION "1"
#endif
#define JS_VBC4_MANIFEST_PREFIX JS_VBC4_MANIFEST_MAGIC "|" JS_VBC4_MANIFEST_VERSION "|"
#endif

typedef struct {
    char original[JS_VM_CALL_GATE_KEY_LEN];
    char sealed[JS_VM_CALL_GATE_KEY_LEN];
    uint32_t original_hash;
    int active;
} js_vm_resource_alias_entry;

typedef struct {
    char path[JS_VM_CALL_GATE_KEY_LEN];
    int raw_len;
    int partition_id;
    unsigned char digest[32];
    uint32_t path_hash;
} js_vm_resource_commitment;

static js_vm_call_gate_entry js_vm_call_gate[JS_VM_CALL_GATE_SIZE];
static js_vm_resource_alias_entry js_vm_resource_aliases[JS_VM_CALL_GATE_SIZE];
/* Values are entry index + 1; zero is an empty slot. */
static uint16_t js_vm_resource_alias_index[JS_VM_RESOURCE_INDEX_SIZE];
static int js_vm_call_gate_count = 0;
static js_vm_resource_commitment *js_vm_commitments = NULL;
static int js_vm_commitment_count = 0;
static uint16_t *js_vm_commitment_index = NULL;
static size_t js_vm_commitment_index_capacity = 0;
static js_vm_ephemeral_cache_entry *js_vm_ephemeral_cache = NULL;
static js_vm_aken_cache_entry *js_vm_aken_prepared_cache = NULL;
static size_t js_vm_aken_prepared_cache_count = 0u;
static int js_vm_aken_prepared_cache_has_active(void);
#ifdef _WIN32
static CRITICAL_SECTION js_vm_cache_lock;
static volatile LONG js_vm_cache_lock_ready = 0;
#else
static pthread_mutex_t js_vm_cache_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
JS_HIDDEN volatile int js_vm_preload_in_progress = 0;

/* Incremented whenever the authenticated resource index/session is replaced
 * or cleared.  It is public only as an opaque generation value so per-thread
 * decompression/JNI caches can reject stale state without retaining secrets. */
static _Atomic unsigned int js_vm_resource_session_generation = 1u;

JS_HIDDEN unsigned int js_vm_resource_session_generation_current(void) {
    unsigned int generation = atomic_load_explicit(&js_vm_resource_session_generation, memory_order_acquire);
    return generation != 0u ? generation : 1u;
}

static void js_vm_resource_session_generation_bump(void) {
    unsigned int current = atomic_load_explicit(&js_vm_resource_session_generation, memory_order_relaxed);
    for (;;) {
        unsigned int next = current + 1u;
        if (next == 0u) next = 1u;
        if (atomic_compare_exchange_weak_explicit(
                &js_vm_resource_session_generation,
                &current,
                next,
                memory_order_release,
                memory_order_relaxed)) return;
    }
}

static uint32_t js_vm_resource_hash(const char *text) {
    uint32_t hash = 2166136261u;
    if (!text) return hash;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        hash ^= (uint32_t)*p;
        hash *= 16777619u;
    }
    return hash;
}

static int js_vm_resource_alias_lookup_locked(const char *path, uint32_t hash) {
    if (!path || !path[0]) return -1;
    const uint32_t mask = JS_VM_RESOURCE_INDEX_SIZE - 1u;
    uint32_t slot = hash & mask;
    for (uint32_t probe = 0; probe < JS_VM_RESOURCE_INDEX_SIZE; ++probe) {
        uint16_t encoded = js_vm_resource_alias_index[slot];
        if (encoded == 0u) return -1;
        int index = (int)encoded - 1;
        if (index >= 0 && index < JS_VM_CALL_GATE_SIZE) {
            js_vm_resource_alias_entry *entry = &js_vm_resource_aliases[index];
            if (entry->active && entry->original_hash == hash && strcmp(entry->original, path) == 0) return index;
        }
        slot = (slot + 1u) & mask;
    }
    return -1;
}

static int js_vm_resource_alias_insert_locked(int index) {
    if (index < 0 || index >= JS_VM_CALL_GATE_SIZE || !js_vm_resource_aliases[index].active) return 0;
    const uint32_t mask = JS_VM_RESOURCE_INDEX_SIZE - 1u;
    uint32_t slot = js_vm_resource_aliases[index].original_hash & mask;
    for (uint32_t probe = 0; probe < JS_VM_RESOURCE_INDEX_SIZE; ++probe) {
        if (js_vm_resource_alias_index[slot] == 0u) {
            js_vm_resource_alias_index[slot] = (uint16_t)(index + 1);
            return 1;
        }
        slot = (slot + 1u) & mask;
    }
    return 0;
}

static int js_vm_commitment_lookup_locked(const char *path, uint32_t hash) {
    if (!path || !path[0] || !js_vm_commitment_index || js_vm_commitment_index_capacity == 0u) return -1;
    const size_t mask = js_vm_commitment_index_capacity - 1u;
    size_t slot = (size_t)hash & mask;
    for (size_t probe = 0; probe < js_vm_commitment_index_capacity; ++probe) {
        uint16_t encoded = js_vm_commitment_index[slot];
        if (encoded == 0u) return -1;
        int index = (int)encoded - 1;
        if (index >= 0 && index < js_vm_commitment_count) {
            js_vm_resource_commitment *entry = &js_vm_commitments[index];
            if (entry->path_hash == hash && strcmp(entry->path, path) == 0) return index;
        }
        slot = (slot + 1u) & mask;
    }
    return -1;
}

static int js_vm_commitment_insert_locked(int index) {
    if (index < 0 || index >= js_vm_commitment_count || !js_vm_commitment_index || js_vm_commitment_index_capacity == 0u) return 0;
    const size_t mask = js_vm_commitment_index_capacity - 1u;
    size_t slot = (size_t)js_vm_commitments[index].path_hash & mask;
    for (size_t probe = 0; probe < js_vm_commitment_index_capacity; ++probe) {
        if (js_vm_commitment_index[slot] == 0u) {
            js_vm_commitment_index[slot] = (uint16_t)(index + 1);
            return 1;
        }
        slot = (slot + 1u) & mask;
    }
    return 0;
}

JS_HIDDEN char js_vm_last_prepare_stage[96] = {0};

static void js_vm_set_prepare_stage(const char *s) {
    if (!s) { js_vm_last_prepare_stage[0] = 0; return; }
    size_t n = strlen(s);
    if (n >= sizeof(js_vm_last_prepare_stage)) n = sizeof(js_vm_last_prepare_stage) - 1;
    memcpy(js_vm_last_prepare_stage, s, n);
    js_vm_last_prepare_stage[n] = 0;
}

static int js_vm_prepare_stage_has_prefix(const char *prefix) {
    if (!prefix) return 0;
    size_t n = strlen(prefix);
    return n > 0 && strncmp(js_vm_last_prepare_stage, prefix, n) == 0;
}

typedef struct {
    ZSTD_DCtx *dctx;
    /* Static decoder workspace.  It holds only the per-thread decoder state;
     * decompressed plaintext is always written directly to caller-owned
     * output and never retained in this cache. */
    unsigned char *scratch;
    size_t scratch_capacity;
    unsigned int dctx_is_static;
    unsigned int generation;
} js_vm_zstd_context_state;

/* The decoder workspace is never sized from artifact-controlled plaintext
 * length.  `ZSTD_estimateDCtxSize()` is a fixed implementation bound for the
 * one-shot decoder used here; the explicit cap makes a future zstd update
 * fail closed instead of retaining unbounded per-thread state. */
#define JS_VM_ZSTD_SCRATCH_MAX ((size_t)256u * 1024u)

static void js_vm_zstd_context_release_buffers(js_vm_zstd_context_state *state) {
    if (!state) return;
    if (state->dctx) {
        if (!state->dctx_is_static) (void)ZSTD_freeDCtx(state->dctx);
        state->dctx = NULL;
        state->dctx_is_static = 0u;
    }
    if (state->scratch) {
        /* Wipe the complete capacity, not just the last decoded length.  This
         * keeps failed/short decodes from leaving bytes in a retained buffer. */
        js_vbc4_wipe_volatile(state->scratch, state->scratch_capacity);
        free(state->scratch);
        state->scratch = NULL;
        state->scratch_capacity = 0u;
    }
}

static int js_vm_zstd_context_prepare_dctx(js_vm_zstd_context_state *state) {
    if (!state) return 0;
    if (state->dctx && state->dctx_is_static && state->scratch && state->scratch_capacity != 0u) return 1;
    js_vm_zstd_context_release_buffers(state);
    size_t workspace_size = ZSTD_estimateDCtxSize();
    if (workspace_size == 0u || workspace_size > JS_VM_ZSTD_SCRATCH_MAX) return 0;
    state->scratch = (unsigned char *)malloc(workspace_size);
    if (!state->scratch) return 0;
    state->scratch_capacity = workspace_size;
    state->dctx = ZSTD_initStaticDCtx(state->scratch, state->scratch_capacity);
    if (!state->dctx) {
        js_vm_zstd_context_release_buffers(state);
        return 0;
    }
    state->dctx_is_static = 1u;
    return 1;
}

#ifdef _WIN32
static DWORD js_vm_zstd_fls_index = FLS_OUT_OF_INDEXES;
static volatile LONG js_vm_zstd_fls_state = 0;

static VOID CALLBACK js_vm_zstd_context_destructor(PVOID value) {
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)value;
    if (!state) return;
    js_vm_zstd_context_release_buffers(state);
    js_vbc4_wipe_volatile(state, sizeof(*state));
    free(state);
}

static int js_vm_zstd_context_key_init(void) {
    LONG state = InterlockedCompareExchange(&js_vm_zstd_fls_state, 2, 0);
    if (state == 0) {
        DWORD index = FlsAlloc(js_vm_zstd_context_destructor);
        if (index == FLS_OUT_OF_INDEXES) {
            InterlockedExchange(&js_vm_zstd_fls_state, -1);
            return 0;
        }
        js_vm_zstd_fls_index = index;
        InterlockedExchange(&js_vm_zstd_fls_state, 1);
    } else {
        while (js_vm_zstd_fls_state == 2) SwitchToThread();
    }
    return js_vm_zstd_fls_state == 1 && js_vm_zstd_fls_index != FLS_OUT_OF_INDEXES;
}

static js_vm_zstd_context_state *js_vm_zstd_context_get(void) {
    if (!js_vm_zstd_context_key_init()) return NULL;
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)FlsGetValue(js_vm_zstd_fls_index);
    if (!state) {
        state = (js_vm_zstd_context_state *)calloc(1, sizeof(*state));
        if (!state || !FlsSetValue(js_vm_zstd_fls_index, state)) {
            if (state) free(state);
            return NULL;
        }
    }
    return state;
}
#else
static pthread_key_t js_vm_zstd_context_key;
static pthread_once_t js_vm_zstd_context_key_once = PTHREAD_ONCE_INIT;
static volatile int js_vm_zstd_context_key_ready = 0;

static void js_vm_zstd_context_destructor(void *value) {
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)value;
    if (!state) return;
    js_vm_zstd_context_release_buffers(state);
    js_vbc4_wipe_volatile(state, sizeof(*state));
    free(state);
}

static void js_vm_zstd_context_key_init_once(void) {
    if (pthread_key_create(&js_vm_zstd_context_key, js_vm_zstd_context_destructor) == 0) {
        js_vm_zstd_context_key_ready = 1;
    }
}

static js_vm_zstd_context_state *js_vm_zstd_context_get(void) {
    (void)pthread_once(&js_vm_zstd_context_key_once, js_vm_zstd_context_key_init_once);
    if (!js_vm_zstd_context_key_ready) return NULL;
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)pthread_getspecific(js_vm_zstd_context_key);
    if (!state) {
        state = (js_vm_zstd_context_state *)calloc(1, sizeof(*state));
        if (!state || pthread_setspecific(js_vm_zstd_context_key, state) != 0) {
            if (state) free(state);
            return NULL;
        }
    }
    return state;
}
#endif

#if defined(JS_ZSTD_CONTEXT_TEST_HOOKS) && JS_ZSTD_CONTEXT_TEST_HOOKS
JS_HIDDEN size_t js_vm_zstd_scratch_capacity_current_thread(void) {
#ifdef _WIN32
    if (js_vm_zstd_fls_state != 1 || js_vm_zstd_fls_index == FLS_OUT_OF_INDEXES) return 0u;
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)FlsGetValue(js_vm_zstd_fls_index);
#else
    if (!js_vm_zstd_context_key_ready) return 0u;
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)pthread_getspecific(js_vm_zstd_context_key);
#endif
    return state ? state->scratch_capacity : 0u;
}

static volatile unsigned int js_vm_zstd_test_partial_output_wipe_seen = 0u;

JS_HIDDEN void js_vm_zstd_test_reset_partial_output_observation(void) {
    js_vm_zstd_test_partial_output_wipe_seen = 0u;
}

static void js_vm_zstd_test_observe_failure_output(const unsigned char *plain, size_t plain_len) {
    unsigned char diff = 0u;
    if (!plain || plain_len == 0u) return;
    for (size_t index = 0u; index < plain_len; ++index) diff |= plain[index];
    if (diff != 0u) js_vm_zstd_test_partial_output_wipe_seen = 1u;
}

JS_HIDDEN unsigned int js_vm_zstd_test_partial_output_wipe_observed(void) {
    return js_vm_zstd_test_partial_output_wipe_seen;
}
#endif

static void js_vm_zstd_wipe_failed_output(unsigned char *plain, size_t plain_len) {
#if defined(JS_ZSTD_CONTEXT_TEST_HOOKS) && JS_ZSTD_CONTEXT_TEST_HOOKS
    js_vm_zstd_test_observe_failure_output(plain, plain_len);
#endif
    js_vbc4_wipe_volatile(plain, plain_len);
}

static void js_vm_zstd_context_reset_current_thread(void) {
#ifdef _WIN32
    if (js_vm_zstd_fls_state != 1 || js_vm_zstd_fls_index == FLS_OUT_OF_INDEXES) return;
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)FlsGetValue(js_vm_zstd_fls_index);
    if (!state) return;
    js_vm_zstd_context_release_buffers(state);
    js_vbc4_wipe_volatile(state, sizeof(*state));
#else
    if (!js_vm_zstd_context_key_ready) return;
    js_vm_zstd_context_state *state = (js_vm_zstd_context_state *)pthread_getspecific(js_vm_zstd_context_key);
    if (!state) return;
    js_vm_zstd_context_release_buffers(state);
    js_vbc4_wipe_volatile(state, sizeof(*state));
#endif
}

JS_HIDDEN unsigned char* js_vbc4_zstd_decompress_owned(const unsigned char *stored, uint32_t stored_len, uint32_t plain_len) {
    js_runtime_metrics_note_structure_check();
    if (!stored || stored_len == 0) return NULL;
    js_runtime_metrics_note_length_check();
    if (stored_len == plain_len) {
        unsigned char *plain_copy = (unsigned char*)malloc((size_t)plain_len);
        if (!plain_copy) return NULL;
        memcpy(plain_copy, stored, (size_t)plain_len);
        return plain_copy;
    }
    unsigned char *plain = plain_len == 0 ? (unsigned char*)calloc(1, 1) : (unsigned char*)malloc((size_t)plain_len);
    if (!plain) return NULL;
#if defined(JS_ZSTD_CONTEXT_TEST_HOOKS) && JS_ZSTD_CONTEXT_TEST_HOOKS
    /* Make the test-only observation deterministic: bytes written before a
     * malformed-frame failure become nonzero, while untouched output remains
     * zero and is still wiped by the production cleanup path. */
    memset(plain, 0, (size_t)plain_len);
#endif
    js_vm_zstd_context_state *state = js_vm_zstd_context_get();
    if (!state) {
        js_vm_zstd_wipe_failed_output(plain, (size_t)plain_len);
        free(plain);
        return NULL;
    }
    unsigned int generation = js_vm_resource_session_generation_current();
    int reused = state->dctx != NULL && state->dctx_is_static != 0u && state->generation == generation;
    if (state->generation != generation) {
        js_vm_zstd_context_release_buffers(state);
        state->generation = generation;
    }
    if (!js_vm_zstd_context_prepare_dctx(state)) {
        js_vm_zstd_wipe_failed_output(plain, (size_t)plain_len);
        free(plain);
        return NULL;
    }
    if (reused) js_runtime_metrics_note_decompress_context_reuse();
    size_t reset_status = ZSTD_DCtx_reset(state->dctx, ZSTD_reset_session_only);
    if (ZSTD_isError(reset_status)) {
        js_vm_zstd_context_release_buffers(state);
        js_vm_zstd_wipe_failed_output(plain, (size_t)plain_len);
        free(plain);
        return NULL;
    }
    size_t written = ZSTD_decompressDCtx(state->dctx, plain, (size_t)plain_len, stored, (size_t)stored_len);
    if (ZSTD_isError(written) || written != (size_t)plain_len) {
        js_vm_zstd_wipe_failed_output(plain, (size_t)plain_len);
        free(plain);
        return NULL;
    }
    /* A resource session may be invalidated while the decoder is running on
     * another thread.  Do not return bytes produced by a context that was
     * valid only for the superseded generation. */
    if (js_vm_resource_session_generation_current() != generation) {
        js_vm_zstd_wipe_failed_output(plain, (size_t)plain_len);
        free(plain);
        js_vm_zstd_context_release_buffers(state);
        state->generation = js_vm_resource_session_generation_current();
        return NULL;
    }
    return plain;
}

static void js_vm_cache_lock_enter(void) {
#ifdef _WIN32
    if (js_vm_cache_lock_ready) EnterCriticalSection(&js_vm_cache_lock);
#else
    pthread_mutex_lock(&js_vm_cache_lock);
#endif
}

static void js_vm_cache_lock_leave(void) {
#ifdef _WIN32
    if (js_vm_cache_lock_ready) LeaveCriticalSection(&js_vm_cache_lock);
#else
    pthread_mutex_unlock(&js_vm_cache_lock);
#endif
}

JS_HIDDEN void js_vm_symbol_cache_lock_enter(void) { js_vm_cache_lock_enter(); }
JS_HIDDEN void js_vm_symbol_cache_lock_leave(void) { js_vm_cache_lock_leave(); }

JS_HIDDEN void js_vm_cache_lock_init(void) {
#ifdef _WIN32
    if (!js_vm_cache_lock_ready) {
        InitializeCriticalSection(&js_vm_cache_lock);
        js_vm_cache_lock_ready = 1;
    }
#endif
}

JS_HIDDEN void js_vm_cache_lock_destroy(void) {
#ifdef _WIN32
    if (js_vm_cache_lock_ready) {
        /* JNI_OnUnload normally arrives after native callers quiesce.  If an
         * active AKEN lease is still draining, keep the lock alive so its
         * release path cannot touch a deleted CRITICAL_SECTION. */
        if (js_vm_aken_prepared_cache_has_active()) return;
        DeleteCriticalSection(&js_vm_cache_lock);
        js_vm_cache_lock_ready = 0;
    }
#endif
}

/*
 * AKEN prepared-program cache
 * ----------------------------
 *
 * The JNI page bridge authenticates the locator, descriptor, route, every
 * sibling page, and the payload before calling these helpers.  Consequently a
 * cache hit only removes the second parse/prepare pass; it never replaces a
 * page-open or authentication step.  Keys are public binding digests rather
 * than raw handles/proofs, and the entry owns no page bytes, nonce, or key
 * material.  A single active lease is intentional: resident opcode state is
 * mutable during execution, so concurrent callers must prepare an independent
 * program instead of sharing a mutable resident image.
 */
static int js_vm_aken_cache_digest(
    const unsigned char *bytes,
    size_t length,
    unsigned char out[32]
) {
    if (!out) return 0;
    memset(out, 0, 32u);
    if (!bytes || length == 0u || length > (size_t)INT_MAX) return 0;
    js_runtime_sha256(bytes, (int)length, out);
    return 1;
}

static jobject js_vm_aken_cache_loader(JNIEnv *env, jclass helper_cls) {
    if (!env || !helper_cls) return NULL;
    /* js_vm_helper_class_loader returns a local reference and clears lookup
     * failures.  A NULL result is the legitimate bootstrap-loader identity. */
    return js_vm_helper_class_loader(env, helper_cls);
}

static int js_vm_aken_cache_loader_matches(JNIEnv *env, const js_vm_aken_cache_entry *entry, jobject loader) {
    if (!entry || !env) return 0;
    if (entry->loader_global) {
        return loader != NULL && (*env)->IsSameObject(env, entry->loader_global, loader) == JNI_TRUE;
    }
    return loader == NULL;
}

static void js_vm_aken_cache_entry_destroy(JNIEnv *env, js_vm_aken_cache_entry *entry) {
    if (!entry) return;
    if (env && entry->loader_global) {
        (*env)->DeleteGlobalRef(env, entry->loader_global);
        entry->loader_global = NULL;
    }
    if (entry->program) {
        js_vm_free_program(env, entry->program);
        free(entry->program);
        entry->program = NULL;
    }
    js_vbc4_wipe_volatile(entry, sizeof(*entry));
    free(entry);
}

static void js_vm_aken_cache_unlink_locked(js_vm_aken_cache_entry *entry) {
    js_vm_aken_cache_entry **cursor = &js_vm_aken_prepared_cache;
    while (*cursor) {
        if (*cursor == entry) {
            *cursor = entry->next;
            entry->next = NULL;
            if (js_vm_aken_prepared_cache_count > 0u) js_vm_aken_prepared_cache_count--;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

JS_HIDDEN js_vm_program* js_vm_aken_prepared_cache_acquire(
    JNIEnv *env,
    jclass helper_cls,
    jlong entry_token,
    jint page_index,
    uint32_t page_count,
    const unsigned char *encoded_handle,
    size_t encoded_handle_len,
    const unsigned char *call_site_proof,
    size_t call_site_proof_len,
    const unsigned char *artifact_commitment,
    size_t artifact_commitment_len,
    const unsigned char *layout_digest,
    size_t layout_digest_len,
    const char *logical_binding_path,
    js_vm_aken_cache_entry **out_lease
) {
    unsigned char handle_digest[32] = {0};
    unsigned char proof_digest[32] = {0};
    unsigned char stale_to_free = 0u;
    js_vm_aken_cache_entry *found = NULL;
    js_vm_aken_cache_entry *stale = NULL;
    jobject loader = NULL;
    if (out_lease) *out_lease = NULL;
    if (!env || !helper_cls || !out_lease || entry_token == 0 || page_index < 0 || page_count == 0u ||
        !encoded_handle || encoded_handle_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE ||
        !call_site_proof || call_site_proof_len == 0u || call_site_proof_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE ||
        !artifact_commitment || artifact_commitment_len != 32u || !layout_digest || layout_digest_len != 32u ||
        !logical_binding_path || !logical_binding_path[0] ||
        !js_vm_aken_cache_digest(encoded_handle, encoded_handle_len, handle_digest) ||
        !js_vm_aken_cache_digest(call_site_proof, call_site_proof_len, proof_digest)) {
        goto cleanup;
    }
    loader = js_vm_aken_cache_loader(env, helper_cls);
    js_vm_cache_lock_enter();
    for (js_vm_aken_cache_entry *entry = js_vm_aken_prepared_cache; entry; entry = entry->next) {
        if (entry->retired || entry->active_users != 0u) continue;
        if (entry->entry_token != entry_token || entry->page_index != page_index || entry->page_count != page_count ||
            entry->session_generation != js_vm_resource_session_generation_current() ||
            memcmp(entry->encoded_handle_digest, handle_digest, 32u) != 0 ||
            memcmp(entry->call_site_proof_digest, proof_digest, 32u) != 0 ||
            memcmp(entry->artifact_commitment, artifact_commitment, 32u) != 0 ||
            memcmp(entry->layout_digest, layout_digest, 32u) != 0) continue;
        if (!js_vm_aken_cache_loader_matches(env, entry, loader) ||
            !entry->program || !entry->program->resource_path ||
            strcmp(entry->program->resource_path, logical_binding_path) != 0 ||
            entry->program->entry_token != entry_token || !entry->program->session_layout_digest_bound ||
            memcmp(entry->program->session_layout_digest, layout_digest, 32u) != 0 ||
            !js_vm_verify_runtime_session(entry->program)) {
            stale = entry;
            break;
        }
        entry->active_users = 1u;
        found = entry;
        break;
    }
    if (stale) {
        js_vm_aken_cache_unlink_locked(stale);
        stale_to_free = 1u;
    }
    js_vm_cache_lock_leave();
    if (stale_to_free) js_vm_aken_cache_entry_destroy(env, stale);
    if (found) *out_lease = found;
cleanup:
    if (loader) (*env)->DeleteLocalRef(env, loader);
    js_vbc4_wipe_volatile(handle_digest, sizeof(handle_digest));
    js_vbc4_wipe_volatile(proof_digest, sizeof(proof_digest));
    return found ? found->program : NULL;
}

JS_HIDDEN int js_vm_aken_prepared_cache_publish(
    JNIEnv *env,
    jclass helper_cls,
    jlong entry_token,
    jint page_index,
    uint32_t page_count,
    const unsigned char *encoded_handle,
    size_t encoded_handle_len,
    const unsigned char *call_site_proof,
    size_t call_site_proof_len,
    const unsigned char *artifact_commitment,
    size_t artifact_commitment_len,
    const unsigned char *layout_digest,
    size_t layout_digest_len,
    const char *logical_binding_path,
    js_vm_program *program,
    js_vm_aken_cache_entry **out_lease
) {
    unsigned char handle_digest[32] = {0};
    unsigned char proof_digest[32] = {0};
    js_vm_aken_cache_entry *entry = NULL;
    js_vm_aken_cache_entry *evicted = NULL;
    jobject loader = NULL;
    jobject loader_global = NULL;
    int inserted = 0;
    if (out_lease) *out_lease = NULL;
    if (!env || !helper_cls || !out_lease || !program || entry_token == 0 || page_index < 0 || page_count == 0u ||
        !encoded_handle || encoded_handle_len != JS_AKEN_NATIVE_PAGE_ENVELOPE_HANDLE_SIZE ||
        !call_site_proof || call_site_proof_len == 0u || call_site_proof_len > JS_AKEN_NATIVE_PAGE_ENVELOPE_MAX_SIZE ||
        !artifact_commitment || artifact_commitment_len != 32u || !layout_digest || layout_digest_len != 32u ||
        !logical_binding_path || !logical_binding_path[0] || !program->session_bound ||
        program->entry_token != entry_token || !program->resource_path || strcmp(program->resource_path, logical_binding_path) != 0 ||
        !program->session_layout_digest_bound || memcmp(program->session_layout_digest, layout_digest, 32u) != 0 ||
        !js_vm_verify_runtime_session(program) ||
        !js_vm_aken_cache_digest(encoded_handle, encoded_handle_len, handle_digest) ||
        !js_vm_aken_cache_digest(call_site_proof, call_site_proof_len, proof_digest)) goto cleanup;
    loader = js_vm_aken_cache_loader(env, helper_cls);
    if (loader) {
        loader_global = (*env)->NewGlobalRef(env, loader);
        if (!loader_global) goto cleanup;
    }
    js_vm_cache_lock_enter();
    /* A concurrent producer may have won the race. Keep the caller-owned
     * program in that case; it remains a one-shot, authenticated execution. */
    for (js_vm_aken_cache_entry *existing = js_vm_aken_prepared_cache; existing; existing = existing->next) {
        if (!existing->retired && existing->entry_token == entry_token && existing->page_index == page_index &&
            existing->page_count == page_count && existing->session_generation == js_vm_resource_session_generation_current() &&
            memcmp(existing->encoded_handle_digest, handle_digest, 32u) == 0 &&
            memcmp(existing->call_site_proof_digest, proof_digest, 32u) == 0 &&
            memcmp(existing->artifact_commitment, artifact_commitment, 32u) == 0 &&
            memcmp(existing->layout_digest, layout_digest, 32u) == 0) {
            js_vm_cache_lock_leave();
            goto cleanup;
        }
    }
    if (js_vm_aken_prepared_cache_count >= JS_VM_AKEN_PREPARED_CACHE_CAPACITY) {
        for (js_vm_aken_cache_entry *candidate = js_vm_aken_prepared_cache; candidate; candidate = candidate->next) {
            if (!candidate->retired && candidate->active_users == 0u) { evicted = candidate; break; }
        }
        if (evicted) js_vm_aken_cache_unlink_locked(evicted);
        else {
            js_vm_cache_lock_leave();
            goto cleanup;
        }
    }
    entry = (js_vm_aken_cache_entry *)calloc(1, sizeof(*entry));
    if (!entry) {
        js_vm_cache_lock_leave();
        if (evicted) js_vm_aken_cache_entry_destroy(env, evicted);
        evicted = NULL;
        goto cleanup;
    }
    entry->entry_token = entry_token;
    entry->page_index = page_index;
    entry->page_count = page_count;
    memcpy(entry->encoded_handle_digest, handle_digest, 32u);
    memcpy(entry->call_site_proof_digest, proof_digest, 32u);
    memcpy(entry->artifact_commitment, artifact_commitment, 32u);
    memcpy(entry->layout_digest, layout_digest, 32u);
    entry->session_generation = js_vm_resource_session_generation_current();
    entry->loader_global = loader_global;
    loader_global = NULL;
    entry->program = program;
    entry->active_users = 1u;
    entry->next = js_vm_aken_prepared_cache;
    js_vm_aken_prepared_cache = entry;
    js_vm_aken_prepared_cache_count++;
    *out_lease = entry;
    inserted = 1;
    js_vm_cache_lock_leave();
    if (evicted) js_vm_aken_cache_entry_destroy(env, evicted);
cleanup:
    if (loader_global && env) (*env)->DeleteGlobalRef(env, loader_global);
    if (loader) (*env)->DeleteLocalRef(env, loader);
    js_vbc4_wipe_volatile(handle_digest, sizeof(handle_digest));
    js_vbc4_wipe_volatile(proof_digest, sizeof(proof_digest));
    return inserted;
}

JS_HIDDEN void js_vm_aken_prepared_cache_release(JNIEnv *env, js_vm_aken_cache_entry *lease) {
    int destroy = 0;
    if (!lease) return;
    js_vm_cache_lock_enter();
    if (lease->active_users > 0u) lease->active_users--;
    if (lease->retired && lease->active_users == 0u) {
        js_vm_aken_cache_unlink_locked(lease);
        destroy = 1;
    }
    js_vm_cache_lock_leave();
    if (destroy) js_vm_aken_cache_entry_destroy(env, lease);
}

static void js_vm_aken_prepared_cache_clear(JNIEnv *env) {
    js_vm_aken_cache_entry *to_free = NULL;
    js_vm_cache_lock_enter();
    js_vm_aken_cache_entry **cursor = &js_vm_aken_prepared_cache;
    while (*cursor) {
        js_vm_aken_cache_entry *entry = *cursor;
        if (entry->active_users != 0u) {
            entry->retired = 1u;
            cursor = &entry->next;
            continue;
        }
        *cursor = entry->next;
        entry->next = to_free;
        to_free = entry;
        if (js_vm_aken_prepared_cache_count > 0u) js_vm_aken_prepared_cache_count--;
    }
    js_vm_cache_lock_leave();
    while (to_free) {
        js_vm_aken_cache_entry *next = to_free->next;
        to_free->next = NULL;
        js_vm_aken_cache_entry_destroy(env, to_free);
        to_free = next;
    }
}

static int js_vm_aken_prepared_cache_has_active(void) {
    int active = 0;
    js_vm_cache_lock_enter();
    for (js_vm_aken_cache_entry *entry = js_vm_aken_prepared_cache; entry; entry = entry->next) {
        if (entry->active_users != 0u) {
            active = 1;
            break;
        }
    }
    js_vm_cache_lock_leave();
    return active;
}

JS_HIDDEN int js_vm_resource_alias_register(const char *original_path, const char *sealed_path) {
    if (!original_path || !sealed_path || !original_path[0] || !sealed_path[0]) return 0;
    /* Reject instead of truncating: aliases are authenticated path bindings. */
    if (strlen(original_path) >= JS_VM_CALL_GATE_KEY_LEN || strlen(sealed_path) >= JS_VM_CALL_GATE_KEY_LEN) return 0;
    if (strcmp(original_path, sealed_path) == 0) return 1;
    const uint32_t original_hash = js_vm_resource_hash(original_path);
    js_vm_cache_lock_enter();
    int existing_index = js_vm_resource_alias_lookup_locked(original_path, original_hash);
    if (existing_index >= 0) {
        int result = strcmp(js_vm_resource_aliases[existing_index].sealed, sealed_path) == 0;
        js_vm_cache_lock_leave();
        return result;
    }
    /* A sealed route is an authenticated binding, not a shared alias bucket.
     * Reject a second original path targeting the same sealed route so the
     * immutable index cannot contain ambiguous duplicate aliases. */
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; ++i) {
        if (js_vm_resource_aliases[i].active && strcmp(js_vm_resource_aliases[i].sealed, sealed_path) == 0) {
            js_vm_cache_lock_leave();
            return 0;
        }
        /* The immutable index is keyed by a 32-bit path hash and then checks
         * the full path.  A hash collision is still an ambiguous authenticated
         * binding at registration time, so reject it rather than allowing two
         * aliases to share one hash bucket. */
        if (js_vm_resource_aliases[i].active &&
            js_vm_resource_aliases[i].original_hash == original_hash &&
            strcmp(js_vm_resource_aliases[i].original, original_path) != 0) {
            js_vm_cache_lock_leave();
            return 0;
        }
    }
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        if (!js_vm_resource_aliases[i].active) {
            js_vm_resource_aliases[i].active = 1;
            js_vm_resource_aliases[i].original_hash = original_hash;
            strncpy(js_vm_resource_aliases[i].original, original_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            strncpy(js_vm_resource_aliases[i].sealed, sealed_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            js_vm_resource_aliases[i].original[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            js_vm_resource_aliases[i].sealed[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            if (js_vm_resource_alias_insert_locked(i)) {
                js_vm_cache_lock_leave();
                return 1;
            }
            js_vbc4_wipe_volatile(&js_vm_resource_aliases[i], sizeof(js_vm_resource_aliases[i]));
            js_vm_cache_lock_leave();
            return 0;
        }
    }
    js_vm_cache_lock_leave();
    return 0;
}

JS_HIDDEN int js_vm_resource_alias_resolve_copy(const char *path, char *out, size_t out_capacity) {
    if (!path || !path[0] || !out || out_capacity == 0u || strlen(path) >= out_capacity) return 0;
    const uint32_t hash = js_vm_resource_hash(path);
    js_vm_cache_lock_enter();
    int index = js_vm_resource_alias_lookup_locked(path, hash);
    const char *resolved = index >= 0 ? js_vm_resource_aliases[index].sealed : path;
    size_t resolved_len = strlen(resolved);
    int ok = resolved_len < out_capacity;
    if (ok) {
        memcpy(out, resolved, resolved_len + 1u);
        if (index >= 0) js_runtime_metrics_note_resource_index_hit();
    }
    js_vm_cache_lock_leave();
    return ok;
}

static uint32_t js_vm_call_gate_hash_token(jlong token) {
    uint64_t x = (uint64_t)token;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)(x ^ (x >> 32));
}

JS_HIDDEN int js_vm_call_gate_register_profile(jlong entry_token, const char *resource_path, uint32_t expected_profile) {
    if (entry_token == 0 || !resource_path || !resource_path[0]) return 0;
    if (strlen(resource_path) >= JS_VM_CALL_GATE_KEY_LEN) return 0;
    if (js_vm_call_gate_count >= JS_VM_CALL_GATE_SIZE - 1) return 0;
    uint32_t h = js_vm_call_gate_hash_token(entry_token) % JS_VM_CALL_GATE_SIZE;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        int idx = (int)((h + (uint32_t)i) % JS_VM_CALL_GATE_SIZE);
        if (!js_vm_call_gate[idx].active) {
            js_vm_call_gate[idx].entry_token = entry_token;
            strncpy(js_vm_call_gate[idx].resource_path, resource_path, JS_VM_CALL_GATE_KEY_LEN - 1);
            js_vm_call_gate[idx].resource_path[JS_VM_CALL_GATE_KEY_LEN - 1] = 0;
            js_vm_call_gate[idx].expected_profile = expected_profile;
            js_vm_call_gate[idx].active = 1;
            js_vm_call_gate[idx].loading = 0;
            js_vm_call_gate_count++;
            return 1;
        }
        if (js_vm_call_gate[idx].entry_token == entry_token) {
            return 0;
        }
    }
    return 0;
}

JS_HIDDEN int js_vm_call_gate_register(jlong entry_token, const char *resource_path) {
    return js_vm_call_gate_register_profile(entry_token, resource_path, 0u);
}

JS_HIDDEN const js_vm_call_gate_entry* js_vm_call_gate_lookup(jlong entry_token) {
    if (entry_token == 0) return NULL;
    uint32_t h = js_vm_call_gate_hash_token(entry_token) % JS_VM_CALL_GATE_SIZE;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        int idx = (int)((h + (uint32_t)i) % JS_VM_CALL_GATE_SIZE);
        if (!js_vm_call_gate[idx].active) return NULL;
        if (js_vm_call_gate[idx].entry_token == entry_token) return &js_vm_call_gate[idx];
    }
    return NULL;
}

static js_vm_call_gate_entry* js_vm_call_gate_lookup_mutable(jlong entry_token) {
    if (entry_token == 0) return NULL;
    uint32_t h = js_vm_call_gate_hash_token(entry_token) % JS_VM_CALL_GATE_SIZE;
    for (int i = 0; i < JS_VM_CALL_GATE_SIZE; i++) {
        int idx = (int)((h + (uint32_t)i) % JS_VM_CALL_GATE_SIZE);
        if (!js_vm_call_gate[idx].active) return NULL;
        if (js_vm_call_gate[idx].entry_token == entry_token) return &js_vm_call_gate[idx];
    }
    return NULL;
}

JS_HIDDEN int js_vm_call_gate_mark_loading(jlong entry_token, const char *resource_path) {
    int marked = 0;
    js_vm_cache_lock_enter();
    js_vm_call_gate_entry *entry = js_vm_call_gate_lookup_mutable(entry_token);
    if (entry && resource_path && strcmp(entry->resource_path, resource_path) == 0 && !entry->loading) {
        entry->loading = 1;
        marked = 1;
    }
    js_vm_cache_lock_leave();
    return marked;
}

JS_HIDDEN void js_vm_call_gate_clear_loading(jlong entry_token) {
    js_vm_cache_lock_enter();
    js_vm_call_gate_entry *entry = js_vm_call_gate_lookup_mutable(entry_token);
    if (entry) entry->loading = 0;
    js_vm_cache_lock_leave();
}

static void js_vm_call_gate_wait_pause(void) {
#ifdef _WIN32
    Sleep(1);
#else
    const struct timespec delay = {0, 1000000L};
    (void)nanosleep(&delay, NULL);
#endif
}

JS_HIDDEN js_vm_program* js_vm_call_gate_wait_for_program(jlong entry_token, const char *resource_path) {
    if (entry_token == 0 || !resource_path || !resource_path[0]) return NULL;
    for (int attempt = 0; attempt < JS_VM_PRELOAD_WAIT_ATTEMPTS; attempt++) {
        js_vm_program *cached = js_vm_ephemeral_cache_get(entry_token, resource_path);
        if (cached) return cached;

        int loading = 0;
        js_vm_cache_lock_enter();
        js_vm_call_gate_entry *entry = js_vm_call_gate_lookup_mutable(entry_token);
        if (entry && entry->active && strcmp(entry->resource_path, resource_path) == 0) {
            loading = entry->loading;
        }
        js_vm_cache_lock_leave();

        if (!loading) return js_vm_ephemeral_cache_get(entry_token, resource_path);
        js_vm_call_gate_wait_pause();
    }
    return js_vm_ephemeral_cache_get(entry_token, resource_path);
}

static void js_vm_commitments_reset_unlocked(void) {
    if (js_vm_commitments) {
        js_vbc4_wipe_volatile(js_vm_commitments, (size_t)js_vm_commitment_count * sizeof(*js_vm_commitments));
        free(js_vm_commitments);
    }
    js_vm_commitments = NULL;
    js_vm_commitment_count = 0;
    if (js_vm_commitment_index) {
        js_vbc4_wipe_volatile(js_vm_commitment_index, js_vm_commitment_index_capacity * sizeof(*js_vm_commitment_index));
        free(js_vm_commitment_index);
    }
    js_vm_commitment_index = NULL;
    js_vm_commitment_index_capacity = 0u;
    js_vm_zstd_context_reset_current_thread();
    js_vm_resource_session_generation_bump();
}

JS_HIDDEN void js_vm_call_gate_reset(void) {
    js_vm_cache_lock_enter();
    js_vbc4_wipe_volatile(js_vm_call_gate, sizeof(js_vm_call_gate));
    js_vbc4_wipe_volatile(js_vm_resource_aliases, sizeof(js_vm_resource_aliases));
    js_vbc4_wipe_volatile(js_vm_resource_alias_index, sizeof(js_vm_resource_alias_index));
    js_vm_call_gate_count = 0;
    js_vm_commitments_reset_unlocked();
    js_vm_cache_lock_leave();
}

static int js_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int js_hex_bytes_to_buffer(const char *hex, size_t hex_len, unsigned char *out) {
    if (!hex || !out || (hex_len & 1u) != 0u) return 0;
    for (size_t i = 0; i < hex_len / 2u; i++) {
        int hi = js_hex_nibble(hex[i * 2u]);
        int lo = js_hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

JS_HIDDEN void js_vm_commitments_reset(void) {
    js_vm_cache_lock_enter();
    js_vm_commitments_reset_unlocked();
    js_vm_cache_lock_leave();
}

JS_HIDDEN int js_vm_commitments_install(const unsigned char *bytes, int len) {
    if (!bytes || len <= 0) return 0;
    int expected = 0;
    for (int i = 0; i < len; i++) if ((i == 0 || bytes[i - 1] == '\n') && i + 2 < len && bytes[i] == 'R' && bytes[i + 1] == '|') expected++;
    if (expected <= 0 || expected >= JS_VM_CALL_GATE_SIZE || expected >= (int)JS_VM_RESOURCE_INDEX_SIZE) return 0;
    js_vm_resource_commitment *parsed = (js_vm_resource_commitment*)calloc((size_t)expected, sizeof(*parsed));
    if (!parsed) return 0;
    int parsed_count = 0;
    int line_start = 0;
    for (int i = 0; i <= len; i++) {
        if (i != len && bytes[i] != '\n' && bytes[i] != '\r') continue;
        int line_end = i;
        if (line_end > line_start) {
            int sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1;
            for (int p = line_start; p < line_end; p++) {
                if (bytes[p] != '|') continue;
                if (sep1 < 0) sep1 = p;
                else if (sep2 < 0) sep2 = p;
                else if (sep3 < 0) sep3 = p;
                else { sep4 = p; break; }
            }
            if (sep1 != line_start + 1 || bytes[line_start] != 'R' || sep2 <= sep1 + 1 || sep3 <= sep2 + 1 || sep4 <= sep3 + 1 || sep4 + 1 >= line_end) goto fail;
            int path_len = sep2 - sep1 - 1;
            int length_len = sep3 - sep2 - 1;
            int digest_len = sep4 - sep3 - 1;
            int partition_len = line_end - sep4 - 1;
            if (path_len <= 0 || path_len >= JS_VM_CALL_GATE_KEY_LEN || length_len <= 0 || length_len >= 16 || digest_len != 64 || partition_len <= 0 || partition_len >= 8) goto fail;
            char length_text[16], partition_text[8];
            memcpy(length_text, bytes + sep2 + 1, (size_t)length_len);
            length_text[length_len] = 0;
            memcpy(partition_text, bytes + sep4 + 1, (size_t)partition_len);
            partition_text[partition_len] = 0;
            char *length_end = NULL, *partition_end = NULL;
            long raw_len = strtol(length_text, &length_end, 10);
            long partition_id = strtol(partition_text, &partition_end, 10);
            if (!length_end || *length_end || !partition_end || *partition_end || raw_len <= 0 || raw_len > 0x7fffffffL || partition_id < 0 || partition_id > 16) goto fail;
            if (parsed_count >= expected) goto fail;
            js_vm_resource_commitment *slot = &parsed[parsed_count];
            memcpy(slot->path, bytes + sep1 + 1, (size_t)path_len);
            slot->path[path_len] = 0;
            slot->raw_len = (int)raw_len;
            slot->partition_id = (int)partition_id;
            if (!js_hex_bytes_to_buffer((const char*)bytes + sep3 + 1, 64, slot->digest)) goto fail;
            for (int prior = 0; prior < parsed_count; prior++) if (strcmp(parsed[prior].path, slot->path) == 0) goto fail;
            parsed_count++;
        }
        while (i + 1 < len && (bytes[i + 1] == '\n' || bytes[i + 1] == '\r')) i++;
        line_start = i + 1;
    }
    if (parsed_count != expected) goto fail;
    size_t index_capacity = 1u;
    while (index_capacity < (size_t)parsed_count * 2u && index_capacity < JS_VM_RESOURCE_INDEX_SIZE) index_capacity <<= 1u;
    if (index_capacity < (size_t)parsed_count * 2u || index_capacity > JS_VM_RESOURCE_INDEX_SIZE) goto fail;
    uint16_t *index = (uint16_t *)calloc(index_capacity, sizeof(*index));
    if (!index) goto fail;
    for (int i = 0; i < parsed_count; ++i) {
        parsed[i].path_hash = js_vm_resource_hash(parsed[i].path);
        for (int prior = 0; prior < i; ++prior) {
            /* Do not retain two authenticated routes under one hash.  The
             * lookup compares the full path, but accepting a duplicate hash
             * would make the immutable commitment index ambiguous under a
             * collision and violate fail-closed duplicate registration. */
            if (parsed[i].path_hash == parsed[prior].path_hash &&
                strcmp(parsed[i].path, parsed[prior].path) != 0) {
                goto fail;
            }
        }
    }
    js_vm_cache_lock_enter();
    js_vm_commitments_reset_unlocked();
    js_vm_commitments = parsed;
    js_vm_commitment_count = parsed_count;
    js_vm_commitment_index = index;
    js_vm_commitment_index_capacity = index_capacity;
    int indexed = 1;
    for (int i = 0; i < parsed_count; ++i) {
        if (!js_vm_commitment_insert_locked(i)) { indexed = 0; break; }
    }
    if (!indexed) {
        js_vm_commitments_reset_unlocked();
        js_vm_cache_lock_leave();
        return 0;
    }
    js_vm_cache_lock_leave();
    return 1;
fail:
    js_vbc4_wipe_volatile(parsed, (size_t)expected * sizeof(*parsed));
    free(parsed);
    return 0;
}

JS_HIDDEN int js_vm_commitment_matches(const char *path, const unsigned char *raw, int raw_len) {
    js_runtime_metrics_note_structure_check();
    if (!path || !raw || raw_len <= 0) return 0;
    js_vm_resource_commitment entry;
    memset(&entry, 0, sizeof(entry));
    const uint32_t hash = js_vm_resource_hash(path);
    js_vm_cache_lock_enter();
    int index = js_vm_commitment_lookup_locked(path, hash);
    if (index >= 0) {
        entry = js_vm_commitments[index];
        js_runtime_metrics_note_resource_index_hit();
    }
    js_vm_cache_lock_leave();
    if (index < 0) return 0;
    js_runtime_metrics_note_length_check();
    if (entry.raw_len != raw_len || raw_len < 27 || raw[0] != 'J' || raw[1] != 'S' || raw[2] != 'R' || raw[3] != 'P' || raw[4] != 8) return 0;
    int partition_id = (int)raw[25] | ((int)raw[26] << 8);
    if (partition_id != entry.partition_id) return 0;
    unsigned char digest[32];
    js_runtime_metrics_note_digest_check();
    js_runtime_sha256(raw, raw_len, digest);
    unsigned char diff = 0;
    for (int j = 0; j < 32; j++) diff |= (unsigned char)(digest[j] ^ entry.digest[j]);
    js_vbc4_wipe_volatile(digest, sizeof(digest));
    js_vbc4_wipe_volatile(&entry, sizeof(entry));
    return diff == 0;
}

JS_HIDDEN int js_hex32_to_bytes(const char *hex, unsigned char out[32]) {
    if (!hex || !out) return 0;
    for (int i = 0; i < 32; i++) {
        int hi = js_hex_nibble(hex[i * 2]);
        int lo = js_hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return hex[64] == 0 || hex[64] == '|';
}

JS_HIDDEN int js_parse_u32_token(const char *text, uint32_t *out) {
    if (!text || !text[0] || !out) return 0;
    uint64_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10u + (uint64_t)(*p - '0');
        if (value > 0xFFFFFFFFULL) return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

JS_HIDDEN int js_parse_hex_u32_token(const char *text, uint32_t *out) {
    if (!text || !text[0] || !out) return 0;
    uint64_t value = 0;
    for (const unsigned char *p = (const unsigned char*)text; *p; p++) {
        unsigned int nibble;
        if (*p >= '0' && *p <= '9') nibble = (unsigned int)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') nibble = (unsigned int)(*p - 'a' + 10);
        else if (*p >= 'A' && *p <= 'F') nibble = (unsigned int)(*p - 'A' + 10);
        else return 0;
        value = value * 16u + nibble;
        if (value > 0xFFFFFFFFULL) return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

JS_HIDDEN char* js_next_manifest_field(char **cursor) {
    if (!cursor || !*cursor) return NULL;
    char *start = *cursor;
    char *sep = strchr(start, '|');
    if (sep) {
        *sep = 0;
        *cursor = sep + 1;
    } else {
        char *end = start + strlen(start);
        while (end > start && (end[-1] == '\n' || end[-1] == '\r')) *--end = 0;
        *cursor = NULL;
    }
    return start;
}

static void js_vm_resource_clear_exception(JNIEnv *env) {
    if (env && (*env)->ExceptionCheck(env)) {
        js_runtime_metrics_note_exception();
        (*env)->ExceptionClear(env);
    }
}

JS_HIDDEN jobject js_vm_class_resource_as_stream(JNIEnv *env, jobject class_obj, jstring resource_path) {
    if (!class_obj || !resource_path || !js_jni_cache_validate(env, (jclass)class_obj)) return NULL;
    jobject loader = (*env)->CallNonvirtualObjectMethod(env, class_obj, js_jni_cache.class_class, js_jni_cache.class_get_class_loader);
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    const char *raw_path = j2c(env, resource_path);
    if (!raw_path) { js_vm_resource_clear_exception(env); return NULL; }
    char *resolved = NULL;
    if (raw_path[0] == '/') {
        resolved = js_strdup(raw_path + 1);
    } else {
        jstring class_name_j = (jstring)(*env)->CallNonvirtualObjectMethod(env, class_obj, js_jni_cache.class_class, js_jni_cache.class_get_name);
        if ((*env)->ExceptionCheck(env) || !class_name_j) {
            if ((*env)->ExceptionCheck(env)) js_vm_resource_clear_exception(env);
        } else {
            const char *class_name = j2c(env, class_name_j);
            if (class_name) {
                const char *last_dot = strrchr(class_name, '.');
                size_t package_len = last_dot ? (size_t)(last_dot - class_name) : 0;
                size_t path_len = strlen(raw_path);
                resolved = (char*)malloc(package_len + (package_len ? 1 : 0) + path_len + 1);
                if (resolved) {
                    size_t pos = 0;
                    for (size_t i = 0; i < package_len; i++) resolved[pos++] = class_name[i] == '.' ? '/' : class_name[i];
                    if (package_len) resolved[pos++] = '/';
                    memcpy(resolved + pos, raw_path, path_len + 1);
                }
                rls(env, class_name_j, class_name);
            }
            (*env)->DeleteLocalRef(env, class_name_j);
        }
    }
    rls(env, resource_path, raw_path);
    if (!resolved) return NULL;
    jstring resolved_j = (*env)->NewStringUTF(env, resolved);
    free(resolved);
    if (!resolved_j) { js_vm_resource_clear_exception(env); return NULL; }
    jobject stream = loader ? js_vm_resource_from_loader(env, loader, resolved_j) : NULL;
    (*env)->DeleteLocalRef(env, resolved_j);
    if (stream) return stream;
    return (*env)->CallNonvirtualObjectMethod(env, class_obj, js_jni_cache.class_class, js_jni_cache.class_get_resource_as_stream, resource_path);
}

JS_HIDDEN jobject js_vm_resource_from_loader(JNIEnv *env, jobject loader, jstring resourcePath) {
    if (!env || !loader || !resourcePath ||
        !js_jni_cache_validate_loader(env, loader) ||
        !js_jni_cache.class_loader_get_resource_as_stream) return NULL;
    jobject stream = (*env)->CallObjectMethod(env, loader, js_jni_cache.class_loader_get_resource_as_stream, resourcePath);
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    return stream;
}

JS_HIDDEN jobject js_vm_context_class_loader(JNIEnv *env) {
    if (!env || !js_jni_cache_validate(env, NULL) ||
        !js_jni_cache.thread_class || !js_jni_cache.thread_current_thread ||
        !js_jni_cache.thread_get_context_class_loader) return NULL;
    jclass thread_cls = js_jni_cache.thread_class;
    if (!thread_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID current_thread = js_jni_cache.thread_current_thread;
    if (!current_thread) { js_vm_resource_clear_exception(env); return NULL; }
    jobject thread = (*env)->CallStaticObjectMethod(env, thread_cls, current_thread);
    if ((*env)->ExceptionCheck(env) || !thread) { js_vm_resource_clear_exception(env); return NULL; }
    jobject loader = (*env)->CallObjectMethod(env, thread, js_jni_cache.thread_get_context_class_loader);
    (*env)->DeleteLocalRef(env, thread);
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    if (loader && !js_jni_cache_validate_loader(env, loader)) {
        (*env)->DeleteLocalRef(env, loader);
        return NULL;
    }
    return loader;
}

JS_HIDDEN jobject js_vm_helper_class_loader(JNIEnv *env, jclass helper_cls) {
    if (!helper_cls) return NULL;
    (void)js_jni_cache_validate(env, helper_cls);
    jclass class_cls = js_jni_cache.initialized ? js_jni_cache.class_class : (*env)->FindClass(env, "java/lang/Class");
    if (!class_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID get_class_loader = js_jni_cache.initialized ? js_jni_cache.class_get_class_loader : (*env)->GetMethodID(env, class_cls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_class_loader) { js_vm_resource_clear_exception(env); return NULL; }
    jobject loader = (*env)->CallObjectMethod(env, helper_cls, get_class_loader);
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    return loader;
}

static jobject js_vm_resource_from_helper_class(JNIEnv *env, jclass helper_cls, jstring resourcePath) {
    if (!helper_cls || !resourcePath) return NULL;
    (void)js_jni_cache_validate(env, helper_cls);
    const char *path = j2c(env, resourcePath);
    if (!path) { js_vm_resource_clear_exception(env); return NULL; }
    size_t len = strlen(path);
    char *absolute = (char*)malloc(len + 2);
    if (!absolute) { rls(env, resourcePath, path); return NULL; }
    absolute[0] = '/';
    memcpy(absolute + 1, path, len + 1);
    rls(env, resourcePath, path);
    jstring absolute_path = (*env)->NewStringUTF(env, absolute);
    free(absolute);
    if (!absolute_path) { js_vm_resource_clear_exception(env); return NULL; }

    jclass class_cls = js_jni_cache.initialized ? js_jni_cache.class_class : (*env)->FindClass(env, "java/lang/Class");
    if (!class_cls) { js_vm_resource_clear_exception(env); return NULL; }
    jmethodID get_resource = js_jni_cache.initialized ? js_jni_cache.class_get_resource_as_stream : (*env)->GetMethodID(env, class_cls, "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;");
    if (!get_resource) { js_vm_resource_clear_exception(env); return NULL; }
    jobject stream = (*env)->CallObjectMethod(env, helper_cls, get_resource, absolute_path);
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    return stream;
}

static jbyteArray js_vm_read_stream_bytes_legacy(JNIEnv *env, jobject stream, jmethodID read_mid) {
    if (!read_mid) return NULL;
    size_t capacity = 8192;
    size_t used = 0;
    unsigned char *buffer = (unsigned char*)malloc(capacity);
    if (!buffer) return NULL;
    for (;;) {
        if (used == capacity) {
            size_t next = capacity * 2;
            unsigned char *grown = (unsigned char*)realloc(buffer, next);
            if (!grown) { free(buffer); return NULL; }
            buffer = grown;
            capacity = next;
        }
        jsize chunk = (jsize)(capacity - used);
        jbyteArray temp = (*env)->NewByteArray(env, chunk);
        if (!temp) { free(buffer); js_vm_resource_clear_exception(env); return NULL; }
        jint got = (*env)->CallIntMethod(env, stream, read_mid, temp);
        if ((*env)->ExceptionCheck(env)) {
            js_vm_resource_clear_exception(env);
            (*env)->DeleteLocalRef(env, temp);
            free(buffer);
            return NULL;
        }
        if (got < 0) {
            (*env)->DeleteLocalRef(env, temp);
            break;
        }
        if (got > 0) {
            if (used + (size_t)got > capacity) {
                size_t next = capacity;
                while (used + (size_t)got > next) next *= 2;
                unsigned char *grown = (unsigned char*)realloc(buffer, next);
                if (!grown) { (*env)->DeleteLocalRef(env, temp); free(buffer); return NULL; }
                buffer = grown;
                capacity = next;
            }
            (*env)->GetByteArrayRegion(env, temp, 0, got, (jbyte*)(buffer + used));
            used += (size_t)got;
        }
        (*env)->DeleteLocalRef(env, temp);
        if (got == 0) break;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)used);
    if (!result) { free(buffer); js_vm_resource_clear_exception(env); return NULL; }
    if (used > 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)used, (const jbyte*)buffer);
    free(buffer);
    return result;
}

static jbyteArray js_vm_read_stream_bytes(JNIEnv *env, jobject stream) {
    if (!env || !stream || !js_jni_cache_validate(env, NULL) ||
        !js_jni_cache.input_stream_class ||
        !(*env)->IsInstanceOf(env, stream, js_jni_cache.input_stream_class)) {
        if (env) js_vm_resource_clear_exception(env);
        return NULL;
    }
    if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); return NULL; }
    jbyteArray bytes = NULL;
    if (js_jni_cache.input_stream_read_all_bytes) {
        bytes = (jbyteArray)(*env)->CallObjectMethod(env, stream, js_jni_cache.input_stream_read_all_bytes);
        if ((*env)->ExceptionCheck(env)) { js_vm_resource_clear_exception(env); bytes = NULL; }
    } else {
        bytes = js_vm_read_stream_bytes_legacy(env, stream, js_jni_cache.input_stream_read);
    }
    if (js_jni_cache.input_stream_close) (*env)->CallVoidMethod(env, stream, js_jni_cache.input_stream_close);
    js_vm_resource_clear_exception(env);
    return bytes;
}

JS_HIDDEN js_vm_loaded_resource js_vm_load_resource_bytes_with_loader(JNIEnv *env, jclass helper_cls, jstring resourcePath) {
    js_vm_loaded_resource result;
    memset(&result, 0, sizeof(result));
    if (!resourcePath) return result;
    jobject loader = NULL;
    jobject stream = NULL;
    int loader_is_borrowed = 0;
    if (!js_vm_preload_in_progress) {
        loader = js_vm_get_active_host_loader();
        loader_is_borrowed = loader != NULL;
        stream = js_vm_resource_from_loader(env, loader, resourcePath);
    }
    if (!stream) {
        if (loader && !loader_is_borrowed) (*env)->DeleteLocalRef(env, loader);
        loader = NULL;
        loader_is_borrowed = 0;
        loader = js_vm_context_class_loader(env);
        stream = js_vm_resource_from_loader(env, loader, resourcePath);
    }
    if (!stream) {
        if (loader && !loader_is_borrowed) (*env)->DeleteLocalRef(env, loader);
        loader = NULL;
        loader_is_borrowed = 0;
        loader = js_vm_helper_class_loader(env, helper_cls);
        stream = js_vm_resource_from_loader(env, loader, resourcePath);
    }
    if (!stream) {
        if (loader && !loader_is_borrowed) (*env)->DeleteLocalRef(env, loader);
        loader = NULL;
        loader_is_borrowed = 0;
        stream = js_vm_resource_from_helper_class(env, helper_cls, resourcePath);
    }
    result.bytes = js_vm_read_stream_bytes(env, stream);
    if (stream) (*env)->DeleteLocalRef(env, stream);
    if (!result.bytes && loader && !loader_is_borrowed) {
        (*env)->DeleteLocalRef(env, loader);
        loader = NULL;
    }
    /* The active dispatch loader belongs to its enclosing VM execution scope.
     * js_vm_loaded_resource exposes only locally acquired fallback loaders for
     * caller cleanup; returning the borrowed active loader lets a page slice
     * release the outer scope's JNI reference and leaves subsequent sibling
     * page loads with a dangling jobject. */
    result.loader = result.bytes && loader && !loader_is_borrowed ? loader : NULL;
    return result;
}

JS_HIDDEN jbyteArray js_vm_load_resource_bytes(JNIEnv *env, jclass helper_cls, jstring resourcePath) {
    js_vm_loaded_resource loaded = js_vm_load_resource_bytes_with_loader(env, helper_cls, resourcePath);
    if (loaded.loader) (*env)->DeleteLocalRef(env, loaded.loader);
    return loaded.bytes;
}

JS_HIDDEN unsigned char* js_vm_decode_resource_path_owned(JNIEnv *env, jclass helper_cls, const char *path, int *out_len) {
    if (!path || !path[0] || !out_len) return NULL;
    char load_path[JS_VM_CALL_GATE_KEY_LEN] = {0};
    if (!js_vm_resource_alias_resolve_copy(path, load_path, sizeof(load_path))) return NULL;
    jstring path_j = (*env)->NewStringUTF(env, load_path);
    if (!path_j) {
        js_clear_pending_exception(env);
        js_vbc4_wipe_volatile(load_path, sizeof(load_path));
        return NULL;
    }
    js_vm_loaded_resource loaded = js_vm_load_resource_bytes_with_loader(env, helper_cls, path_j);
    (*env)->DeleteLocalRef(env, path_j);
    if (!loaded.bytes) {
        if (loaded.loader) (*env)->DeleteLocalRef(env, loaded.loader);
        js_vbc4_wipe_volatile(load_path, sizeof(load_path));
        return NULL;
    }
    int raw_len = (*env)->GetArrayLength(env, loaded.bytes);
    jbyte *raw_bytes = raw_len > 0 ? (*env)->GetByteArrayElements(env, loaded.bytes, NULL) : NULL;
    unsigned char *decoded = NULL;
    if (raw_bytes) {
        if (js_vm_commitment_matches(load_path, (const unsigned char*)raw_bytes, raw_len)) {
            decoded = js_runtime_resource_decode_owned((const unsigned char*)raw_bytes, raw_len, out_len);
        }
        js_vbc4_wipe_volatile(raw_bytes, (size_t)raw_len);
        (*env)->ReleaseByteArrayElements(env, loaded.bytes, raw_bytes, JNI_ABORT);
    }
    if (loaded.bytes) (*env)->DeleteLocalRef(env, loaded.bytes);
    if (loaded.loader) (*env)->DeleteLocalRef(env, loaded.loader);
    js_vbc4_wipe_volatile(load_path, sizeof(load_path));
    return decoded;
}

static int js_hex16_is_valid(const char *text) {
    if (!text || strlen(text) != 16u) return 0;
    for (int i = 0; i < 16; i++) if (js_hex_nibble(text[i]) < 0) return 0;
    return 1;
}

static void js_sha256_hex16(unsigned char digest[32], char out[17]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[16] = 0;
}

static void js_sha256_update_cstr(js_sha256_ctx *ctx, const char *text) {
    js_sha256_update(ctx, (const unsigned char*)text, (int)strlen(text));
}

static void js_sha256_update_zero(js_sha256_ctx *ctx) {
    static const unsigned char zero = 0;
    js_sha256_update(ctx, &zero, 1);
}

JS_PROTECTED static int js_manifest_mesh_link_matches(const char *mesh, uint32_t ordinal, uint32_t index, uint32_t offset, uint32_t length, const char *digest, const char *path, const char *expected) {
    if (!mesh || !digest || !path || !expected || !js_hex16_is_valid(expected)) return 0;
    char ordinal_text[16], index_text[16], offset_text[16], length_text[16];
    snprintf(ordinal_text, sizeof(ordinal_text), "%u", ordinal);
    snprintf(index_text, sizeof(index_text), "%u", index);
    snprintf(offset_text, sizeof(offset_text), "%u", offset);
    snprintf(length_text, sizeof(length_text), "%u", length);
    unsigned char digest_bytes[32];
    char actual[17];
    js_sha256_ctx ctx;
    js_sha256_init(&ctx);
    js_sha256_update_cstr(&ctx, mesh); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, ordinal_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, index_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, offset_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, length_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, digest); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, path);
    js_sha256_final(&ctx, digest_bytes);
    js_sha256_hex16(digest_bytes, actual);
    js_vbc4_wipe_volatile(digest_bytes, sizeof(digest_bytes));
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    return strcmp(actual, expected) == 0;
}

JS_PROTECTED static int js_manifest_peer_link_matches(const char *mesh, uint32_t ordinal, uint32_t entry_count, uint32_t index, uint32_t offset, uint32_t length, const char *digest, const char *path, uint32_t peer_ordinal, const char *expected) {
    if (!mesh || !digest || !path || !expected || !js_hex16_is_valid(expected)) return 0;
    char ordinal_text[16], entry_count_text[16], index_text[16], offset_text[16], length_text[16], peer_ordinal_text[16];
    snprintf(ordinal_text, sizeof(ordinal_text), "%u", ordinal);
    snprintf(entry_count_text, sizeof(entry_count_text), "%u", entry_count);
    snprintf(index_text, sizeof(index_text), "%u", index);
    snprintf(offset_text, sizeof(offset_text), "%u", offset);
    snprintf(length_text, sizeof(length_text), "%u", length);
    snprintf(peer_ordinal_text, sizeof(peer_ordinal_text), "%u", peer_ordinal);
    unsigned char digest_bytes[32];
    char actual[17];
    js_sha256_ctx ctx;
    js_sha256_init(&ctx);
    js_sha256_update_cstr(&ctx, "vbc4-peer-link"); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, mesh); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, ordinal_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, entry_count_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, index_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, offset_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, length_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, digest); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, path); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, peer_ordinal_text);
    js_sha256_final(&ctx, digest_bytes);
    js_sha256_hex16(digest_bytes, actual);
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= (int)((unsigned char)actual[i] ^ (unsigned char)expected[i]);
    js_vbc4_wipe_volatile(digest_bytes, sizeof(digest_bytes));
    js_vbc4_wipe_volatile(actual, sizeof(actual));
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    return diff == 0;
}

JS_PROTECTED static int js_manifest_order_token(const char *mesh, uint32_t ordinal, uint32_t index, const char *path, const char *digest, char out[17]) {
    if (!mesh || !path || !digest || !out) return 0;
    char ordinal_text[16], index_text[16];
    snprintf(ordinal_text, sizeof(ordinal_text), "%u", ordinal);
    snprintf(index_text, sizeof(index_text), "%u", index);
    unsigned char digest_bytes[32];
    js_sha256_ctx ctx;
    js_sha256_init(&ctx);
    js_sha256_update_cstr(&ctx, "vbc4-shard-order"); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, mesh); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, ordinal_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, index_text); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, path); js_sha256_update_zero(&ctx);
    js_sha256_update_cstr(&ctx, digest);
    js_sha256_final(&ctx, digest_bytes);
    js_sha256_hex16(digest_bytes, out);
    js_vbc4_wipe_volatile(digest_bytes, sizeof(digest_bytes));
    js_vbc4_wipe_volatile(&ctx, sizeof(ctx));
    return 1;
}

JS_HIDDEN unsigned char* js_vm_reassemble_sliced_resource(JNIEnv *env, jclass helper_cls, unsigned char *decoded, int decoded_len, int *out_len) {
#if defined(JS_AKEN_TYPED_ONLY_RUNTIME) && JS_AKEN_TYPED_ONLY_RUNTIME
    const size_t manifest_prefix_len = 8u;
    if (!decoded || decoded_len <= (int)manifest_prefix_len || !out_len ||
        !js_aken_legacy_manifest_prefix_matches(decoded, (size_t)decoded_len)) return decoded;
#else
    const size_t manifest_prefix_len = sizeof(JS_VBC4_MANIFEST_PREFIX) - 1u;
    if (!decoded || decoded_len <= (int)manifest_prefix_len || !out_len ||
        memcmp(decoded, JS_VBC4_MANIFEST_PREFIX, manifest_prefix_len) != 0) return decoded;
#endif
    char *manifest = (char*)calloc((size_t)decoded_len + 1u, 1u);
    if (!manifest) { js_vm_set_prepare_stage("reassemble-manifest-alloc"); return NULL; }
    memcpy(manifest, decoded, (size_t)decoded_len);
    js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
    free(decoded);
    decoded = NULL;

    char *line = manifest;
    char *next_line = strchr(line, '\n');
    if (!next_line) { js_vm_set_prepare_stage("reassemble-manifest-newline"); js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL; }
    *next_line++ = 0;
    char *cursor = line;
    char *magic = js_next_manifest_field(&cursor);
    char *version = js_next_manifest_field(&cursor);
    char *total_text = js_next_manifest_field(&cursor);
    char *count_text = js_next_manifest_field(&cursor);
    char *mesh_text = js_next_manifest_field(&cursor);
    char *ordinal_text = js_next_manifest_field(&cursor);
    char *entry_count_text = js_next_manifest_field(&cursor);
    uint32_t total_len = 0;
    uint32_t shard_count = 0;
    uint32_t manifest_ordinal = 0;
    uint32_t manifest_entry_count = 0;
#if defined(JS_AKEN_TYPED_ONLY_RUNTIME) && JS_AKEN_TYPED_ONLY_RUNTIME
    if (!js_aken_legacy_manifest_header_matches(magic, version) ||
#else
    if (!magic || strcmp(magic, JS_VBC4_MANIFEST_MAGIC) != 0 ||
        !version || strcmp(version, JS_VBC4_MANIFEST_VERSION) != 0 ||
#endif
        !js_parse_u32_token(total_text, &total_len) || !js_parse_u32_token(count_text, &shard_count) ||
        !mesh_text || strlen(mesh_text) != 64u || !js_parse_u32_token(ordinal_text, &manifest_ordinal) ||
        !js_parse_u32_token(entry_count_text, &manifest_entry_count) || manifest_entry_count == 0 ||
        manifest_ordinal >= manifest_entry_count || total_len == 0 || shard_count < 2 || shard_count > 16 ||
        total_len > 64u * 1024u * 1024u) {
        js_vm_set_prepare_stage("reassemble-header");
        js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL;
    }
    unsigned char mesh_digest_bytes[32];
    if (!js_hex32_to_bytes(mesh_text, mesh_digest_bytes)) {
        js_vm_set_prepare_stage("reassemble-mesh-digest");
        js_vbc4_wipe_volatile(mesh_digest_bytes, sizeof(mesh_digest_bytes));
        js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL;
    }
    js_vbc4_wipe_volatile(mesh_digest_bytes, sizeof(mesh_digest_bytes));
    unsigned char *assembled = (unsigned char*)calloc((size_t)total_len, 1u);
    unsigned char *seen = (unsigned char*)calloc((size_t)shard_count, 1u);
    char (*order_tokens)[17] = (char (*)[17])calloc((size_t)shard_count, sizeof(*order_tokens));
    if (!assembled || !seen || !order_tokens) {
        js_vm_set_prepare_stage("reassemble-alloc");
        if (assembled) free(assembled);
        if (seen) free(seen);
        if (order_tokens) free(order_tokens);
        js_vbc4_wipe_volatile(manifest, (size_t)decoded_len); free(manifest); return NULL;
    }
    int ok = 1;
    uint32_t loaded_count = 0;
    line = next_line;
    while (line && *line && ok) {
        char *line_end = strchr(line, '\n');
        if (line_end) *line_end = 0;
        char *field_cursor = line;
        char *index_text = js_next_manifest_field(&field_cursor);
        char *offset_text = js_next_manifest_field(&field_cursor);
        char *length_text = js_next_manifest_field(&field_cursor);
        char *sha_text = js_next_manifest_field(&field_cursor);
        char *path_text = js_next_manifest_field(&field_cursor);
        char *mesh_link_text = js_next_manifest_field(&field_cursor);
        char *peer_ordinal_text = js_next_manifest_field(&field_cursor);
        char *peer_link_text = js_next_manifest_field(&field_cursor);
        uint32_t index = 0, offset = 0, length = 0, peer_ordinal = 0;
        unsigned char expected_sha[32];
        memset(expected_sha, 0, sizeof(expected_sha));
        if (!js_parse_u32_token(index_text, &index) || !js_parse_u32_token(offset_text, &offset) ||
            !js_parse_u32_token(length_text, &length) || !js_parse_u32_token(peer_ordinal_text, &peer_ordinal) ||
            index >= shard_count || seen[index] || peer_ordinal >= manifest_entry_count ||
            (manifest_entry_count > 1 && peer_ordinal == manifest_ordinal) || length == 0 || offset > total_len ||
            length > total_len - offset || !sha_text || strlen(sha_text) != 64 ||
            !js_hex32_to_bytes(sha_text, expected_sha) || !path_text || !path_text[0] ||
            !js_hex16_is_valid(mesh_link_text) || !js_hex16_is_valid(peer_link_text)) {
            js_vm_set_prepare_stage("reassemble-row");
            ok = 0;
        } else {
            char expected_order_token[17];
            if (!js_manifest_mesh_link_matches(mesh_text, manifest_ordinal, index, offset, length, sha_text, path_text, mesh_link_text) ||
                !js_manifest_peer_link_matches(mesh_text, manifest_ordinal, manifest_entry_count, index, offset, length, sha_text, path_text, peer_ordinal, peer_link_text) ||
                !js_manifest_order_token(mesh_text, manifest_ordinal, index, path_text, sha_text, expected_order_token) ||
                (loaded_count > 0 && strcmp(order_tokens[loaded_count - 1], expected_order_token) > 0)) {
                js_vm_set_prepare_stage("reassemble-mesh-link");
                ok = 0;
            }
            if (ok) memcpy(order_tokens[loaded_count], expected_order_token, sizeof(expected_order_token));
            int shard_len = 0;
            unsigned char *shard = js_vm_decode_resource_path_owned(env, helper_cls, path_text, &shard_len);
            if (!shard || shard_len != (int)length) {
                js_vm_set_prepare_stage("reassemble-shard-load");
                ok = 0;
            } else {
                unsigned char actual_sha[32];
                js_sha256_ctx sha_ctx;
                js_sha256_init(&sha_ctx);
                js_sha256_update(&sha_ctx, shard, shard_len);
                js_sha256_final(&sha_ctx, actual_sha);
                if (memcmp(actual_sha, expected_sha, 32) != 0) {
                    js_vm_set_prepare_stage("reassemble-shard-digest");
                    ok = 0;
                } else {
                    memcpy(assembled + offset, shard, (size_t)length);
                    seen[index] = 1;
                    loaded_count++;
                }
                js_vbc4_wipe_volatile(actual_sha, sizeof(actual_sha));
                js_vbc4_wipe_volatile(&sha_ctx, sizeof(sha_ctx));
            }
            js_vbc4_wipe_volatile(expected_sha, sizeof(expected_sha));
            if (shard) { js_vbc4_wipe_volatile(shard, (size_t)(shard_len > 0 ? shard_len : 0)); free(shard); }
        }
        line = line_end ? line_end + 1 : NULL;
    }
    for (uint32_t i = 0; ok && i < shard_count; i++) if (!seen[i]) { js_vm_set_prepare_stage("reassemble-missing-shard"); ok = 0; }
    if (loaded_count != shard_count) { js_vm_set_prepare_stage("reassemble-count"); ok = 0; }
    js_vbc4_wipe_volatile(order_tokens, (size_t)shard_count * sizeof(*order_tokens));
    free(order_tokens);
    js_vbc4_wipe_volatile(seen, (size_t)shard_count);
    free(seen);
    js_vbc4_wipe_volatile(manifest, (size_t)decoded_len);
    free(manifest);
    if (!ok) {
        js_vbc4_wipe_volatile(assembled, (size_t)total_len);
        free(assembled);
        return NULL;
    }
    *out_len = (int)total_len;
    return assembled;
}

JS_PROTECTED int js_vm_register_preload_index_entries(const unsigned char *index_bytes, int index_len) {
    if (!index_bytes || index_len <= 0) return 0;
    int ok = 1;
    int line_start = 0;
    for (int i = 0; i <= index_len; i++) {
        if (i != index_len && index_bytes[i] != '\n' && index_bytes[i] != '\r') continue;
        int line_end = i;
        while (line_start < line_end && (index_bytes[line_start] == ' ' || index_bytes[line_start] == '\t')) line_start++;
        while (line_end > line_start && (index_bytes[line_end - 1] == ' ' || index_bytes[line_end - 1] == '\t')) line_end--;
        if (line_end > line_start) {
            int sep1 = -1, sep2 = -1, sep3 = -1, sep4 = -1, sep5 = -1, sep6 = -1, sep7 = -1, sep8 = -1;
            for (int p = line_start; p < line_end; p++) {
                if (index_bytes[p] != '|') continue;
                if (sep1 < 0) sep1 = p;
                else if (sep2 < 0) sep2 = p;
                else if (sep3 < 0) sep3 = p;
                else if (sep4 < 0) sep4 = p;
                else if (sep5 < 0) sep5 = p;
                else if (sep6 < 0) sep6 = p;
                else if (sep7 < 0) sep7 = p;
                else { sep8 = p; break; }
            }
            if (sep1 == line_start + 1 && index_bytes[line_start] == 'A' && sep2 > sep1 + 1 && sep2 + 1 < line_end) {
                char *original_path = js_substr_dup((const char*)index_bytes + sep1 + 1, (size_t)(sep2 - sep1 - 1));
                char *sealed_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(line_end - sep2 - 1));
                if (!original_path || !sealed_path || !js_vm_resource_alias_register(original_path, sealed_path)) ok = 0;
                if (original_path) { js_vbc4_wipe_volatile(original_path, strlen(original_path)); free(original_path); }
                if (sealed_path) { js_vbc4_wipe_volatile(sealed_path, strlen(sealed_path)); free(sealed_path); }
                while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
                line_start = i + 1;
                continue;
            }
            if (sep1 > line_start && sep1 + 1 < line_end && sep1 - line_start <= 16) {
                unsigned long long token = 0;
                int valid = 1;
                for (int p = line_start; p < sep1; p++) {
                    unsigned char ch = index_bytes[p];
                    int nibble = (ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' && ch <= 'f') ? (ch - 'a' + 10) : (ch >= 'A' && ch <= 'F') ? (ch - 'A' + 10) : -1;
                    if (nibble < 0) { valid = 0; break; }
                    token = (token << 4) | (unsigned long long)nibble;
                }
                int path_start = sep1 + 1;
                int path_end = sep2 > 0 ? sep2 : line_end;
                if (valid && path_end > path_start) {
                    char *resource_path = js_substr_dup((const char*)index_bytes + path_start, (size_t)(path_end - path_start));
                    if (resource_path) {
                        char *binding_resource_path = NULL;
                        uint32_t expected_profile = 0u;
                        int authenticated_entry = sep7 > 0 && sep4 > 0 && sep5 > sep4 && sep6 > sep5 && sep7 > sep6;
                        if (authenticated_entry) {
                            int binding_resource_end = sep8 > 0 ? sep8 : line_end;
                            binding_resource_path = js_substr_dup((const char*)index_bytes + sep7 + 1, (size_t)(binding_resource_end - sep7 - 1));
                            char *profile_text = js_substr_dup((const char*)index_bytes + sep5 + 1, (size_t)(sep6 - sep5 - 1));
                            if (profile_text) {
                                if (!js_parse_hex_u32_token(profile_text, &expected_profile)) ok = 0;
                                js_vbc4_wipe_volatile(profile_text, strlen(profile_text));
                                free(profile_text);
                            }
                        } else if (sep4 > 0) {
                            int binding_resource_end = sep5 > 0 ? sep5 : line_end;
                            binding_resource_path = js_substr_dup((const char*)index_bytes + sep4 + 1, (size_t)(binding_resource_end - sep4 - 1));
                        }
                        const char *gate_path = binding_resource_path && binding_resource_path[0] ? binding_resource_path : resource_path;
                        if (!js_vm_call_gate_register_profile((jlong)token, gate_path, expected_profile)) ok = 0;
                        if (binding_resource_path && strcmp(binding_resource_path, resource_path) != 0 && !js_vm_resource_alias_register(binding_resource_path, resource_path)) ok = 0;
                        if (authenticated_entry && sep2 > 0 && sep3 > 0 && sep8 > 0) {
                            char *manifest_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(sep3 - sep2 - 1));
                            char *binding_manifest_path = js_substr_dup((const char*)index_bytes + sep8 + 1, (size_t)(line_end - sep8 - 1));
                            if (manifest_path && binding_manifest_path && strcmp(binding_manifest_path, manifest_path) != 0 && !js_vm_resource_alias_register(binding_manifest_path, manifest_path)) ok = 0;
                            if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                            if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                        } else if (sep2 > 0 && sep3 > 0 && sep5 > 0) {
                            char *manifest_path = js_substr_dup((const char*)index_bytes + sep2 + 1, (size_t)(sep3 - sep2 - 1));
                            char *binding_manifest_path = js_substr_dup((const char*)index_bytes + sep5 + 1, (size_t)(line_end - sep5 - 1));
                            if (manifest_path && binding_manifest_path && strcmp(binding_manifest_path, manifest_path) != 0 && !js_vm_resource_alias_register(binding_manifest_path, manifest_path)) ok = 0;
                            if (manifest_path) { js_vbc4_wipe_volatile(manifest_path, strlen(manifest_path)); free(manifest_path); }
                            if (binding_manifest_path) { js_vbc4_wipe_volatile(binding_manifest_path, strlen(binding_manifest_path)); free(binding_manifest_path); }
                        }
                        if (binding_resource_path) { js_vbc4_wipe_volatile(binding_resource_path, strlen(binding_resource_path)); free(binding_resource_path); }
                        js_vbc4_wipe_volatile(resource_path, strlen(resource_path));
                        free(resource_path);
                    } else {
                        ok = 0;
                    }
                }
                else ok = 0;
            }
        }
        while (i + 1 < index_len && (index_bytes[i + 1] == '\n' || index_bytes[i + 1] == '\r')) i++;
        line_start = i + 1;
    }
    return ok && js_vm_call_gate_count > 0;
}

JS_HIDDEN js_vm_program* js_vm_prepare_resource_program_bound(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, const char *binding_path_override) {
    if (!resourcePath || entry_token == 0) return NULL;
    const char *resource_path = j2c(env, resourcePath);
    if (!resource_path) {
        rls(env, resourcePath, resource_path);
        return NULL;
    }
    char load_resource_path[JS_VM_CALL_GATE_KEY_LEN] = {0};
    if (!js_vm_resource_alias_resolve_copy(resource_path, load_resource_path, sizeof(load_resource_path))) {
        rls(env, resourcePath, resource_path);
        return NULL;
    }
#define JS_VM_PREPARE_RESOURCE_RETURN(value) do { \
        js_vbc4_wipe_volatile(load_resource_path, sizeof(load_resource_path)); \
        rls(env, resourcePath, resource_path); \
        return (value); \
    } while (0)
    jstring loadResourcePath = resourcePath;
    if (strcmp(load_resource_path, resource_path) != 0) {
        loadResourcePath = (*env)->NewStringUTF(env, load_resource_path);
        if (!loadResourcePath) {
            js_vm_clear_exception(env);
            JS_VM_PREPARE_RESOURCE_RETURN(NULL);
        }
    }
    js_vm_loaded_resource loaded = js_vm_load_resource_bytes_with_loader(env, resource_cls, loadResourcePath);
    if (loadResourcePath != resourcePath) (*env)->DeleteLocalRef(env, loadResourcePath);
    if (!loaded.bytes) {
        js_vm_set_prepare_stage("resource-load");
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    int decoded_len = 0;
    unsigned char *decoded = NULL;
    int raw_len = (*env)->GetArrayLength(env, loaded.bytes);
    jbyte *raw_bytes = raw_len > 0 ? (*env)->GetByteArrayElements(env, loaded.bytes, NULL) : NULL;
    if (raw_bytes) {
        if (js_vm_commitment_matches(load_resource_path, (const unsigned char*)raw_bytes, raw_len)) {
            decoded = js_runtime_resource_decode_owned((const unsigned char*)raw_bytes, raw_len, &decoded_len);
        }
        js_vbc4_wipe_volatile(raw_bytes, (size_t)raw_len);
        (*env)->ReleaseByteArrayElements(env, loaded.bytes, raw_bytes, JNI_ABORT);
    }
    if (loaded.bytes) {
        (*env)->DeleteLocalRef(env, loaded.bytes);
        loaded.bytes = NULL;
    }
    if (loaded.loader) {
        (*env)->DeleteLocalRef(env, loaded.loader);
        loaded.loader = NULL;
    }
    if (!decoded) {
        js_vm_set_prepare_stage("decode");
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    decoded = js_vm_reassemble_sliced_resource(env, resource_cls, decoded, decoded_len, &decoded_len);
    if (!decoded) {
        if (!js_vm_prepare_stage_has_prefix("reassemble-")) js_vm_set_prepare_stage("reassemble");
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    js_vm_program *parsed_program = (js_vm_program*)calloc(1, sizeof(js_vm_program));
    if (!parsed_program) {
        js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
        free(decoded);
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    unsigned char binding_buf[1200];
    const char *binding_resource_path = binding_path_override && binding_path_override[0] ? binding_path_override : (resource_path ? resource_path : "");
    int binding_len = js_vm_build_state_binding(entry_token, binding_resource_path, binding_buf, (int)sizeof(binding_buf));
    if (!js_vm_resource_integrity_clean()) {
        js_vm_set_prepare_stage("integrity");
        js_vbc4_wipe_volatile(binding_buf, sizeof(binding_buf));
        js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
        free(decoded);
        js_vm_free_program(env, parsed_program);
        free(parsed_program);
        js_vm_fail_closed(env, NULL);
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    int parsed = binding_len > 0 ? js_vm_parse_program(decoded, decoded_len, parsed_program, binding_buf, binding_len) : 0;
    js_vbc4_wipe_volatile(binding_buf, sizeof(binding_buf));
    js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);
    free(decoded);
    decoded = NULL;
    if (!parsed) {
        char parse_stage[32];
        snprintf(parse_stage, sizeof(parse_stage), "parse-%d", js_vm_last_parse_stage);
        js_vm_set_prepare_stage(parse_stage);
        js_vm_free_program(env, parsed_program);
        free(parsed_program);
        js_vm_fail_closed(env, NULL);
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    js_vm_call_gate_register(entry_token, resource_path);
    parsed_program->entry_token = entry_token;
    parsed_program->return_desc = js_vm_return_descriptor_from_meta(parsed_program, entry_token);
    if (!parsed_program->return_desc) {
        js_vm_set_prepare_stage("return-desc");
        js_vm_free_program(env, parsed_program);
        free(parsed_program);
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    /* Metadata parsing above installs the authenticated method identity and
     * profile. Bind the runtime leaf only after those immutable tag fields are
     * final, otherwise verification would correctly reject the later mutation. */
    if (!js_vm_bind_runtime_session(parsed_program, entry_token, resource_path)) {
        js_vm_set_prepare_stage("session-bind");
        js_vm_free_program(env, parsed_program);
        free(parsed_program);
        JS_VM_PREPARE_RESOURCE_RETURN(NULL);
    }
    js_vbc4_wipe_volatile(load_resource_path, sizeof(load_resource_path));
#undef JS_VM_PREPARE_RESOURCE_RETURN
    rls(env, resourcePath, resource_path);
    return parsed_program;
}

JS_HIDDEN js_vm_program* js_vm_prepare_resource_program(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath) {
    return js_vm_prepare_resource_program_bound(env, resource_cls, entry_token, resourcePath, NULL);
}

#define JS_VM_AKEN_LOGICAL_BINDING_PATH_MAX 1024u

JS_HIDDEN js_vm_program* js_vm_prepare_aken_complete_frame_program(
    JNIEnv *env,
    jlong entry_token,
    const unsigned char *frame,
    size_t frame_len,
    const unsigned char *logical_binding_path,
    size_t logical_binding_path_len,
    const unsigned char *artifact_commitment,
    size_t artifact_commitment_len,
    const unsigned char *state_binding_layout_digest,
    size_t state_binding_layout_digest_len
) {
    js_vm_program *program = NULL;
    js_vm_program validation;
    char *binding_path = NULL;
    unsigned char binding_buf[1200] = {0};
    int binding_len = 0;
    int ok = 0;
    int scoped_layout_digest_installed = 0;
    memset(&validation, 0, sizeof(validation));
    js_vm_set_prepare_stage("aken-input");
    if (!env || entry_token == 0 || !frame || frame_len == 0u || frame_len > (size_t)INT_MAX ||
        !logical_binding_path || logical_binding_path_len == 0u ||
        logical_binding_path_len > JS_VM_AKEN_LOGICAL_BINDING_PATH_MAX ||
        memchr(logical_binding_path, '\0', logical_binding_path_len) != NULL ||
        !artifact_commitment || artifact_commitment_len != 32u ||
        !state_binding_layout_digest || state_binding_layout_digest_len != 32u) {
        goto cleanup;
    }
    binding_path = (char *)malloc(logical_binding_path_len + 1u);
    program = (js_vm_program *)calloc(1, sizeof(js_vm_program));
    if (!binding_path || !program) {
        js_vm_set_prepare_stage("aken-alloc");
        goto cleanup;
    }
    memcpy(binding_path, logical_binding_path, logical_binding_path_len);
    binding_path[logical_binding_path_len] = '\0';

    if (!js_vbc4_install_scoped_layout_digest(state_binding_layout_digest)) {
        js_vm_set_prepare_stage("aken-layout-digest");
        goto cleanup;
    }
    scoped_layout_digest_installed = 1;
    binding_len = js_vm_build_state_binding_with_layout_digest(
        entry_token,
        binding_path,
        state_binding_layout_digest,
        binding_buf,
        (int)sizeof(binding_buf));
    if (binding_len <= 0) {
        js_vm_set_prepare_stage("aken-state-binding");
        goto cleanup;
    }
    if (!js_vm_resource_integrity_clean()) {
        js_vm_set_prepare_stage("aken-integrity");
        goto cleanup;
    }
    if (!js_vm_parse_program(frame, (int)frame_len, program, binding_buf, binding_len)) {
        char parse_stage[32];
        snprintf(parse_stage, sizeof(parse_stage), "aken-parse-%d", js_vm_last_parse_stage);
        js_vm_set_prepare_stage(parse_stage);
        goto cleanup;
    }
    program->entry_token = entry_token;
    program->return_desc = js_vm_return_descriptor_from_meta(program, entry_token);
    if (!program->return_desc) {
        js_vm_set_prepare_stage("aken-return-desc");
        goto cleanup;
    }
    if (!program->resource_path) {
        js_vm_set_prepare_stage("aken-resource-path");
        goto cleanup;
    }
    if (strcmp(program->resource_path, binding_path) != 0) {
        js_vm_set_prepare_stage("aken-resource-binding");
        goto cleanup;
    }
    if (!js_vm_build_execution_program_from_registers(program, &validation) ||
        !js_vm_adopt_validated_execution_program(program, &validation)) {
        js_vm_set_prepare_stage("aken-execution-program");
        goto cleanup;
    }
    js_vm_clear_execution_program(&validation);

    /*
     * The artifact commitment is public integrity material, not a key. In the
     * current transition runtime it supplies an artifact-local session nonce
     * when no legacy preload session exists; an already-installed nonce remains
     * authoritative for a legacy-compatible process.
     */
    (void)js_vm_install_startup_nonce(artifact_commitment, (int)artifact_commitment_len);
    if (!js_vm_bind_runtime_session(program, entry_token, binding_path)) {
        js_vm_set_prepare_stage("aken-session-bind");
        goto cleanup;
    }
    ok = 1;
    js_vm_set_prepare_stage("aken-ready");

cleanup:
    if (scoped_layout_digest_installed) js_vbc4_clear_scoped_layout_digest();
    js_vbc4_wipe_volatile(binding_buf, sizeof(binding_buf));
    js_vm_clear_execution_program(&validation);
    if (binding_path) {
        js_vbc4_wipe_volatile(binding_path, logical_binding_path_len);
        free(binding_path);
    }
    if (!ok && program) {
        js_vm_free_program(env, program);
        free(program);
        program = NULL;
    }
    return program;
}

JS_HIDDEN js_vm_program* js_vm_preload_indexed_program_on_demand(JNIEnv *env, jclass resource_cls, jlong entry_token, const char *resource_path, jstring resourcePath) {
    if (!env || !resource_cls || entry_token == 0 || !resource_path || !resourcePath || !js_vm_preload_in_progress) return NULL;
    const js_vm_call_gate_entry *gate = js_vm_call_gate_lookup(entry_token);
    if (!gate || !gate->active || strcmp(gate->resource_path, resource_path) != 0) return NULL;
    js_vm_program *cached = js_vm_ephemeral_cache_get(entry_token, resource_path);
    if (cached) return cached;
    if (!js_vm_call_gate_mark_loading(entry_token, resource_path)) {
        return js_vm_call_gate_wait_for_program(entry_token, resource_path);
    }
    js_vm_program *program = js_vm_prepare_resource_program_bound(env, resource_cls, entry_token, resourcePath, resource_path);
    if (program && gate->expected_profile != 0u && program->method_local_profile != gate->expected_profile) {
        js_vm_free_program(env, program);
        free(program);
        js_vm_call_gate_clear_loading(entry_token);
        js_vm_fail_closed(env, "native VM preload profile mismatch");
        return NULL;
    }
    if (program) {
        js_vm_program validation;
        memset(&validation, 0, sizeof(validation));
        if (!js_vm_build_execution_program_from_registers(program, &validation)) {
            char reason[384];
            snprintf(reason, sizeof(reason), "native VM preload validation failed for entry=%016llx err=%d reg=%d super=%d insn=%d",
                (unsigned long long)program->entry_token,
                js_vm_last_validation_error, program->reg_program.insn_count, program->reg_program.super_count, program->insn_count);
            js_vm_clear_execution_program(&validation);
            js_vm_free_program(env, program);
            free(program);
            js_vm_call_gate_clear_loading(entry_token);
            js_vm_fail_closed(env, reason);
            return NULL;
        } else if (!js_vm_adopt_validated_execution_program(program, &validation)) {
            js_vm_clear_execution_program(&validation);
            js_vm_free_program(env, program);
            free(program);
            js_vm_call_gate_clear_loading(entry_token);
            js_vm_fail_closed(env, "native VM on-demand validation produced no execution program");
            return NULL;
        } else {
            js_vm_clear_execution_program(&validation);
        }
    }
    if (program && !js_vm_ephemeral_cache_put(entry_token, resource_path, program)) {
        js_vm_free_program(env, program);
        free(program);
        program = NULL;
    }
    js_vm_call_gate_clear_loading(entry_token);
    return program;
}

JS_HIDDEN jobject js_vm_execute_cached_program(JNIEnv *env, jclass resource_cls, js_vm_program *program, jobjectArray args) {
    if (!program) {
        return js_vm_fail_closed(env, "native VM resource was not preloaded");
    }
#ifdef _WIN32
    js_vm_cache_lock_enter();
#endif
    /* Bind the calling class loader for this dispatch frame so VM symbol resolution
     * can resolve application classes from native call contexts. */
    jobject saved_host_loader = js_vm_get_active_host_loader();
    jobject host_loader_ref = NULL;
    if (resource_cls) {
        jobject host_loader = js_vm_helper_class_loader(env, resource_cls);
        if (host_loader) {
            host_loader_ref = (*env)->NewLocalRef(env, host_loader);
            if (host_loader_ref) js_vm_set_active_host_loader(host_loader_ref);
            (*env)->DeleteLocalRef(env, host_loader);
        }
    }
    js_vm_object_result result = js_vm_execute_prepared_program(env, program, args);
    js_vm_set_active_host_loader(saved_host_loader);
    if (host_loader_ref) (*env)->DeleteLocalRef(env, host_loader_ref);
    jobject out = NULL;
    if ((*env)->ExceptionCheck(env)) {
        out = NULL;
    } else {
        out = result.ok ? result.value : js_vm_fail_closed(env, NULL);
    }
#ifdef _WIN32
    js_vm_cache_lock_leave();
#endif
    return out;
}

JS_HIDDEN jobject js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args) {
    if (!resourcePath || entry_token == 0) return js_vm_fail_closed(env, NULL);
    if (!js_vm_execute_hot_path_self_check()) {
       return js_vm_fail_closed(env, NULL);
    }
    const char *resource_path = j2c(env, resourcePath);
    js_vm_program *program = resource_path ? js_vm_ephemeral_cache_get(entry_token, resource_path) : NULL;
    if (!program && resource_path && js_vm_preload_in_progress) {
        program = js_vm_preload_indexed_program_on_demand(env, resource_cls, entry_token, resource_path, resourcePath);
    }
    if (resource_path) rls(env, resourcePath, resource_path);
    if ((*env)->ExceptionCheck(env)) {
        return NULL;
    }
    return js_vm_execute_cached_program(env, resource_cls, program, args);
}

JS_HIDDEN jobject js_vm_execute_resource_by_token(JNIEnv *env, jclass resource_cls, jlong entry_token, jobjectArray args) {
    if (entry_token == 0) return js_vm_fail_closed(env, NULL);
    if (!js_vm_execute_hot_path_self_check()) {
       return js_vm_fail_closed(env, NULL);
    }
    const js_vm_call_gate_entry *gate = js_vm_call_gate_lookup(entry_token);
    if (!gate || !gate->active || !gate->resource_path[0]) {
        return js_vm_fail_closed(env, "native VM token was not preloaded");
    }
    js_vm_program *program = js_vm_ephemeral_cache_get(entry_token, gate->resource_path);
    if (!program && js_vm_preload_in_progress) {
        jstring path_j = (*env)->NewStringUTF(env, gate->resource_path);
        if (path_j) {
            program = js_vm_preload_indexed_program_on_demand(env, resource_cls, entry_token, gate->resource_path, path_j);
            (*env)->DeleteLocalRef(env, path_j);
        } else {
            js_vm_resource_clear_exception(env);
        }
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    return js_vm_execute_cached_program(env, resource_cls, program, args);
}

static js_vm_program *js_vm_preloaded_program_for_primitive_token(JNIEnv *env, jclass resource_cls, jlong entry_token) {
    if (entry_token == 0) { js_vm_fail_closed(env, NULL); return NULL; }
    if (!js_vm_execute_hot_path_self_check()) { js_vm_fail_closed(env, NULL); return NULL; }
    const js_vm_call_gate_entry *gate = js_vm_call_gate_lookup(entry_token);
    if (!gate || !gate->active || !gate->resource_path[0]) {
        js_vm_fail_closed(env, "native VM token was not preloaded");
        return NULL;
    }
    js_vm_program *program = js_vm_ephemeral_cache_get(entry_token, gate->resource_path);
    if (!program && js_vm_preload_in_progress) {
        jstring path_j = (*env)->NewStringUTF(env, gate->resource_path);
        if (path_j) {
            program = js_vm_preload_indexed_program_on_demand(env, resource_cls, entry_token, gate->resource_path, path_j);
            (*env)->DeleteLocalRef(env, path_j);
        } else {
            js_vm_resource_clear_exception(env);
        }
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    if (!program) {
        js_vm_fail_closed(env, "native VM resource was not preloaded");
        return NULL;
    }
    return program;
}

JS_HIDDEN void js_vm_execute_resource_int_void_by_token(JNIEnv *env, jclass resource_cls, jlong entry_token, jint arg0) {
    js_vm_program *program = js_vm_preloaded_program_for_primitive_token(env, resource_cls, entry_token);
    if (!program) return;
#ifdef _WIN32
    js_vm_cache_lock_enter();
#endif
    (void)resource_cls;
    int ok = js_vm_execute_prepared_program_int_void(env, program, arg0);
#ifdef _WIN32
    js_vm_cache_lock_leave();
#endif
    if (!ok && !(*env)->ExceptionCheck(env)) js_vm_fail_closed(env, NULL);
}

JS_HIDDEN jint js_vm_execute_resource_int_by_token(JNIEnv *env, jclass resource_cls, jlong entry_token) {
    js_vm_program *program = js_vm_preloaded_program_for_primitive_token(env, resource_cls, entry_token);
    if (!program) return 0;
#ifdef _WIN32
    js_vm_cache_lock_enter();
#endif
    (void)resource_cls;
    jint value = 0;
    int ok = js_vm_execute_prepared_program_int(env, program, &value);
#ifdef _WIN32
    js_vm_cache_lock_leave();
#endif
    if (!ok && !(*env)->ExceptionCheck(env)) js_vm_fail_closed(env, NULL);
    return ok ? value : 0;
}

JS_HIDDEN jint js_vm_execute_resource_int_int_by_token(JNIEnv *env, jclass resource_cls, jlong entry_token, jint arg0) {
    js_vm_program *program = js_vm_preloaded_program_for_primitive_token(env, resource_cls, entry_token);
    if (!program) return 0;
#ifdef _WIN32
    js_vm_cache_lock_enter();
#endif
    (void)resource_cls;
    jint value = 0;
    int ok = js_vm_execute_prepared_program_int_int(env, program, arg0, &value);
#ifdef _WIN32
    js_vm_cache_lock_leave();
#endif
    if (!ok && !(*env)->ExceptionCheck(env)) js_vm_fail_closed(env, NULL);
    return ok ? value : 0;
}

JS_HIDDEN js_vm_program* js_vm_find_preloaded_program_by_identity(const unsigned char method_identity[32]) {
    if (!method_identity) return NULL;
    js_vm_program *active = js_vm_active_program_find_by_identity(method_identity);
    if (active && active->cached_execution_ready) return active;
    return js_vm_ephemeral_cache_find_by_identity(method_identity);
}

JS_HIDDEN js_vm_program* js_vm_ephemeral_cache_get(jlong entry_token, const char *resource_path) {
    if (!resource_path) return NULL;
    js_vm_cache_lock_enter();
    for (js_vm_ephemeral_cache_entry *entry = js_vm_ephemeral_cache; entry; entry = entry->next) {
        if (entry->entry_token == entry_token && entry->resource_path && strcmp(entry->resource_path, resource_path) == 0) {
            js_vm_program *program = entry->program;
            js_vm_cache_lock_leave();
            return program;
        }
    }
    js_vm_cache_lock_leave();
    return NULL;
}

JS_HIDDEN js_vm_program* js_vm_ephemeral_cache_find_by_identity(const unsigned char method_identity[32]) {
    if (!method_identity) return NULL;
    js_vm_cache_lock_enter();
    js_vm_program *found = NULL;
    for (js_vm_ephemeral_cache_entry *entry = js_vm_ephemeral_cache; entry; entry = entry->next) {
        js_vm_program *program = entry->program;
        if (program && program->cached_execution_ready &&
            memcmp(program->method_identity, method_identity, 32) == 0) { found = program; break; }
    }
    js_vm_cache_lock_leave();
    return found;
}

JS_HIDDEN int js_vm_ephemeral_cache_put(jlong entry_token, const char *resource_path, js_vm_program *program) {
    if (!resource_path || !program) return 0;
    js_vm_cache_lock_enter();
    for (js_vm_ephemeral_cache_entry *existing = js_vm_ephemeral_cache; existing; existing = existing->next) {
        if (existing->entry_token == entry_token && existing->resource_path && strcmp(existing->resource_path, resource_path) == 0) {
            js_vm_cache_lock_leave();
            return 1;
        }
    }
    js_vm_ephemeral_cache_entry *entry = (js_vm_ephemeral_cache_entry*)calloc(1, sizeof(js_vm_ephemeral_cache_entry));
    if (!entry) {
        js_vm_cache_lock_leave();
        return 0;
    }
    entry->resource_path = js_strdup(resource_path);
    if (!entry->resource_path) {
        free(entry);
        js_vm_cache_lock_leave();
        return 0;
    }
    entry->entry_token = entry_token;
    entry->program = program;
    entry->next = js_vm_ephemeral_cache;
    js_vm_ephemeral_cache = entry;
    js_vm_cache_lock_leave();
    return 1;
}

JS_HIDDEN void js_vm_ephemeral_cache_clear(JNIEnv *env) {
    /* Session/preload teardown also retires the authenticated AKEN prepared
     * cache. Active leases remain linked until their caller releases them, so
     * unload/reset cannot free a program still executing on another thread. */
    js_vm_aken_prepared_cache_clear(env);
    js_vm_cache_lock_enter();
    js_vm_ephemeral_cache_entry *entry = js_vm_ephemeral_cache;
    js_vm_ephemeral_cache = NULL;
    js_vm_cache_lock_leave();
    while (entry) {
        js_vm_ephemeral_cache_entry *next = entry->next;
        if (entry->program) { js_vm_free_program(env, entry->program); free(entry->program); }
        if (entry->resource_path) { js_vbc4_wipe_volatile(entry->resource_path, strlen(entry->resource_path)); free(entry->resource_path); }
        js_vbc4_wipe_volatile(entry, sizeof(*entry));
        free(entry);
        entry = next;
    }
}
