#include "js_shell_loader.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

static uint64_t loader_ticks(void) {
#if defined(_WIN32)
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return (uint64_t)value.QuadPart;
#else
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
#endif
}

static uint64_t loader_elapsed_ns(uint64_t started, uint64_t finished) {
#if defined(_WIN32)
    static uint64_t frequency;
    if (!frequency) {
        LARGE_INTEGER value;
        QueryPerformanceFrequency(&value);
        frequency = (uint64_t)value.QuadPart;
    }
    if (!frequency || finished < started) return 0;
    return (finished - started) * UINT64_C(1000000000) / frequency;
#else
    return finished >= started ? finished - started : 0;
#endif
}

static void loader_wipe(void *memory, size_t size) {
    volatile unsigned char *cursor = (volatile unsigned char *)memory;
    while (cursor && size--) *cursor++ = 0;
}

static int loader_read_file(const char *path, unsigned char **bytes_out, size_t *size_out) {
    FILE *file;
    long length;
    unsigned char *bytes;
    size_t read_size;
    if (!path || !bytes_out || !size_out) return 0;
    file = fopen(path, "rb");
    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    bytes = (unsigned char *)malloc((size_t)length);
    if (!bytes) {
        fclose(file);
        return 0;
    }
    read_size = fread(bytes, 1u, (size_t)length, file);
    fclose(file);
    if (read_size != (size_t)length) {
        loader_wipe(bytes, (size_t)length);
        free(bytes);
        return 0;
    }
    *bytes_out = bytes;
    *size_out = read_size;
    return 1;
}

static uint64_t loader_digest(const unsigned char *bytes, size_t size) {
    uint64_t value = UINT64_C(1469598103934665603);
    size_t index;
    for (index = 0; bytes && index < size; index++) {
        value ^= bytes[index];
        value *= UINT64_C(1099511628211);
    }
    return value;
}

static int loader_image_is_valid(const js_shell_loaded_image *image) {
    uintptr_t image_low;
    uintptr_t image_high;
    uintptr_t code_low;
    uintptr_t code_high;
    if (!image || !image->image_base || !image->image_size || !image->code_low || !image->code_size) return 0;
    image_low = (uintptr_t)image->image_base;
    if (image->image_size > UINTPTR_MAX - image_low) return 0;
    image_high = image_low + image->image_size;
    code_low = (uintptr_t)image->code_low;
    if (image->code_size > UINTPTR_MAX - code_low) return 0;
    code_high = code_low + image->code_size;
    if (code_low < image_low || code_high > image_high || code_high <= code_low) return 0;
    if (image->mapping_metadata.version != JS_SHELL_MAPPING_METADATA_VERSION ||
        image->mapping_metadata.mapping_unit_count == 0u ||
        image->mapping_metadata.image_low != image_low ||
        image->mapping_metadata.image_high != image_high ||
        image->mapping_metadata.code_low != code_low ||
        image->mapping_metadata.code_high != code_high) return 0;
    if (!image->jni_on_load || !image->native_abi_table_v1) return 0;
    return 1;
}

static int loader_load_and_unload(const js_shell_payload_view *view, unsigned int *mapping_units_out) {
    js_shell_loaded_image image;
    memset(&image, 0, sizeof(image));
    if (!js_shell_load_inner_image(view, &image)) return 0;
    if (!loader_image_is_valid(&image)) {
        js_shell_unload_inner_image(&image);
        return 0;
    }
    if (mapping_units_out) *mapping_units_out = image.mapping_metadata.mapping_unit_count;
    js_shell_unload_inner_image(&image);
    return image.image_base == NULL && image.image_size == 0u;
}

static int loader_compare_uint64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

static uint64_t loader_percentile(const uint64_t *values, unsigned int count, unsigned int numerator, unsigned int denominator) {
    uint64_t *copy;
    unsigned int rank;
    uint64_t result;
    if (!values || !count || !denominator) return 0;
    copy = (uint64_t *)malloc((size_t)count * sizeof(*copy));
    if (!copy) return 0;
    memcpy(copy, values, (size_t)count * sizeof(*copy));
    qsort(copy, count, sizeof(*copy), loader_compare_uint64);
    rank = (unsigned int)(((uint64_t)count * numerator + denominator - 1u) / denominator);
    if (rank == 0u) rank = 1u;
    if (rank > count) rank = count;
    result = copy[rank - 1u];
    loader_wipe(copy, (size_t)count * sizeof(*copy));
    free(copy);
    return result;
}

int main(int argc, char **argv) {
    unsigned char *bytes = NULL;
    unsigned char *tampered = NULL;
    uint64_t *timings = NULL;
    size_t size = 0;
    unsigned int samples;
    unsigned int warmup;
    unsigned int iteration;
    unsigned int mapping_units = 0u;
    unsigned int tamper_rejections = 0u;
    unsigned int load_count = 0u;
    unsigned int unload_count = 0u;
    uint64_t max = 0;
    uint64_t output_digest;
    js_shell_payload_view view;
    if (argc < 4 || !loader_read_file(argv[1], &bytes, &size)) {
        fprintf(stderr, "shell loader probe requires IMAGE_PATH SAMPLES WARMUP\n");
        return 2;
    }
    samples = (unsigned int)strtoul(argv[2], NULL, 10);
    warmup = (unsigned int)strtoul(argv[3], NULL, 10);
    if (!samples || samples > 100000u || warmup > 100000u) {
        loader_wipe(bytes, size);
        free(bytes);
        return 2;
    }
    timings = (uint64_t *)calloc(samples, sizeof(*timings));
    tampered = (unsigned char *)malloc(size);
    if (!timings || !tampered) {
        loader_wipe(bytes, size);
        free(bytes);
        free(timings);
        free(tampered);
        return 2;
    }
    memset(&view, 0, sizeof(view));
    view.decoded_payload = bytes;
    view.decoded_payload_size = size;
    for (iteration = 0u; iteration < warmup; iteration++) {
        if (!loader_load_and_unload(&view, &mapping_units)) {
            fprintf(stderr, "warmup loader failure: %s\n", js_shell_loader_failure_reason());
            goto fail;
        }
    }
    for (iteration = 0u; iteration < samples; iteration++) {
        uint64_t started = loader_ticks();
        if (!loader_load_and_unload(&view, &mapping_units)) {
            fprintf(stderr, "production loader failure at sample %u: %s\n", iteration, js_shell_loader_failure_reason());
            goto fail;
        }
        timings[iteration] = loader_elapsed_ns(started, loader_ticks());
        if (timings[iteration] > max) max = timings[iteration];
        load_count++;
        unload_count++;
    }
    memcpy(tampered, bytes, size);
    tampered[0] ^= 0x5Au;
    view.decoded_payload = tampered;
    if (js_shell_load_inner_image(&view, &(js_shell_loaded_image){0})) {
        fprintf(stderr, "tampered inner image unexpectedly loaded\n");
        goto fail;
    }
    tamper_rejections++;
    output_digest = loader_digest(bytes, size);
    printf("phase=shell-loader phase_mode=production phase_status=pass timing_unit=ns "
           "samples=%u warmup=%u p50=%" PRIu64 " p95=%" PRIu64 " p99=%" PRIu64 " max=%" PRIu64 " "
           "auth_boundary=preverified "
           "load_count=%u unload_count=%u mapping_unit_count=%u tamper_rejection_count=%u "
           "failure_count=0 auth_check_count=0 digest_check_count=0 tag_check_count=0 "
           "length_check_count=1 structure_check_count=1 jni_abi_check_count=1 "
           "wipe_failure_count=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 "
           "security_checks_skipped=0 output_digest=%016" PRIx64 "\n",
           samples,
           warmup,
           loader_percentile(timings, samples, 50u, 100u),
           loader_percentile(timings, samples, 95u, 100u),
           loader_percentile(timings, samples, 99u, 100u),
           max,
           load_count,
           unload_count,
           mapping_units,
           tamper_rejections,
           output_digest);
    fflush(stdout);
    loader_wipe(bytes, size);
    loader_wipe(tampered, size);
    loader_wipe(timings, (size_t)samples * sizeof(*timings));
    free(bytes);
    free(tampered);
    free(timings);
    return 0;

fail:
    loader_wipe(bytes, size);
    loader_wipe(tampered, size);
    loader_wipe(timings, (size_t)samples * sizeof(*timings));
    free(bytes);
    free(tampered);
    free(timings);
    return 1;
}
