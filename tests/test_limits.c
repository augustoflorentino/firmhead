#define _POSIX_C_SOURCE 200809L
#include "firmhead/firmhead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef FWH_TEST_ZLIB
#include <zlib.h>
#endif

static int failures;

#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static const char *const files[] = {"baseline.bin",        "exposed.bin",          "damaged.bin",
                                    "nested.bin",          "signed_weak.bin",      "signed_images_only.bin",
                                    "signed_well.bin",     "tplink_safeloader.bin", "xiaomi_hdr1.bin",
                                    "mikrotik_npk.bin",    "netgear_chk.bin",      "reolink_pak.bin",
                                    "fwtool_signed.bin",   "fwtool_placeholder.bin", "uimage_multi.bin",
                                    "trx_v2.bin",          "fit_external.bin",     "fit_ambiguous.bin",
                                    "safeloader_salted.bin"};

static unsigned char *load(const char *name, size_t *out_len)
{
    char path[1024];
    unsigned char *buf;
    FILE *f;
    long len;

    snprintf(path, sizeof(path), "%s/%s", FWH_TEST_DATA, name);
    if ((f = fopen(path, "rb")) == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)len + 1);
    if (buf && fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *out_len = (size_t)len;
    return buf;
}

static void open_all(const unsigned char *buf, size_t len)
{
    fwh_image_t *image;
    size_t offset, error_at;
    int format;

    for (offset = 0; offset < len; offset = offset == 63 && len > 128 ? len - 64 : offset + 1)
        for (format = 1; format < FWH_FMT_COUNT; format++) {
            image = NULL;
            if (fwh_open(buf, len, offset, format, NULL, NULL, NULL, &image, &error_at) == FWH_OK)
                fwh_audit(image);
            fwh_image_destroy(image);
        }
}

#ifndef _WIN32
static void test_guard_page(void)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE), i, len, cut, limit, span;
    unsigned char *buf, *map;
    unsigned formats;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if ((buf = load(files[i], &len)) == NULL) {
            failures++;
            continue;
        }
        limit = len < 0x3000 + 4096 ? len : 0x3000 + 4096;
        span = (limit + page - 1) / page * page;
        map = mmap(NULL, span + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || mprotect(map + span, page, PROT_NONE) != 0) {
            failures++;
            free(buf);
            continue;
        }
        for (cut = 0; cut <= limit; cut++) {
            unsigned char *start = map + span - cut;

            memcpy(start, buf, cut);
            fwh_probe(start, cut, 0, &formats);
            open_all(start, cut);
        }
        munmap(map, span + page);
        free(buf);
    }
}
#endif

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
    size_t strings_len;
    unsigned char strings[4096];
} fdt_writer_t;

static void put(fdt_writer_t *w, const void *data, size_t len)
{
    if (w->len + len > w->cap) {
        w->cap = (w->len + len) * 2;
        w->data = realloc(w->data, w->cap);
    }
    memcpy(w->data + w->len, data, len);
    w->len += len;
    while (w->len % 4)
        w->data[w->len++] = 0;
}

static void put_u32(fdt_writer_t *w, unsigned long v)
{
    unsigned char b[4] = {(unsigned char)(v >> 24), (unsigned char)(v >> 16), (unsigned char)(v >> 8),
                          (unsigned char)v};

    put(w, b, 4);
}

static unsigned long string_offset(fdt_writer_t *w, const char *name)
{
    size_t i = 0, n = strlen(name) + 1;

    while (i < w->strings_len) {
        if (strcmp((const char *)w->strings + i, name) == 0)
            return (unsigned long)i;
        i += strlen((const char *)w->strings + i) + 1;
    }
    memcpy(w->strings + w->strings_len, name, n);
    w->strings_len += n;
    return (unsigned long)i;
}

static void begin(fdt_writer_t *w, const char *name)
{
    put_u32(w, 1);
    put(w, name, strlen(name) + 1);
}

static void prop(fdt_writer_t *w, const char *name, const void *value, size_t len)
{
    put_u32(w, 3);
    put_u32(w, (unsigned long)len);
    put_u32(w, string_offset(w, name));
    if (len)
        put(w, value, len);
}

static unsigned char *finish(fdt_writer_t *w, size_t *out_len)
{
    size_t header = 40, total, i;
    unsigned long fields[10];
    unsigned char *out;

    put_u32(w, 9);
    total = header + w->len + w->strings_len;
    out = malloc(total);
    fields[0] = 0xd00dfeed;
    fields[1] = (unsigned long)total;
    fields[2] = (unsigned long)header;
    fields[3] = (unsigned long)(header + w->len);
    fields[4] = (unsigned long)header;
    fields[5] = 17;
    fields[6] = 16;
    fields[7] = 0;
    fields[8] = (unsigned long)w->strings_len;
    fields[9] = (unsigned long)w->len;
    for (i = 0; i < 10; i++) {
        out[4 * i] = (unsigned char)(fields[i] >> 24);
        out[4 * i + 1] = (unsigned char)(fields[i] >> 16);
        out[4 * i + 2] = (unsigned char)(fields[i] >> 8);
        out[4 * i + 3] = (unsigned char)fields[i];
    }
    memcpy(out + header, w->data, w->len);
    memcpy(out + header + w->len, w->strings, w->strings_len);
    free(w->data);
    *out_len = total;
    return out;
}

static unsigned char *adversarial_fit(size_t *out_len, size_t tokens)
{
    fdt_writer_t w;
    char name[256];
    size_t i, used = 0;
    int depth;

    memset(&w, 0, sizeof(w));
    memset(name, 'n', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    begin(&w, "");
    begin(&w, "images");
    begin(&w, "k");
    prop(&w, "data", "x", 1);
    prop(&w, "type", "kernel", 7);
    used = 6;
    for (i = 0; used + 2 < tokens / 2; i++, used += 2) {
        memcpy(name, "hash", 4);
        name[4] = (char)('a' + i % 26);
        name[5] = (char)('a' + i / 26 % 26);
        name[6] = (char)('a' + i / 676 % 26);
        begin(&w, name);
        put_u32(&w, 2);
    }
    put_u32(&w, 2);
    put_u32(&w, 2);
    for (depth = 0; depth < 61; depth++, used++)
        begin(&w, name);
    for (; used + 1 < tokens - 64; used++)
        prop(&w, "x", "", 0);
    for (depth = 0; depth < 61; depth++)
        put_u32(&w, 2);
    put_u32(&w, 2);
    return finish(&w, out_len);
}

static double seconds(void)
{
#ifdef _WIN32
    return (double)clock() / CLOCKS_PER_SEC;
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

typedef struct {
    size_t calls;
    size_t live;
    size_t peak;
} counter_t;

typedef struct {
    size_t size;
    double align;
} block_t;

static void *count_alloc(void *ctx, size_t size)
{
    counter_t *c = ctx;
    block_t *b = malloc(sizeof(block_t) + size);

    if (b == NULL)
        return NULL;
    b->size = size;
    c->calls++;
    c->live += size;
    if (c->live > c->peak)
        c->peak = c->live;
    return b + 1;
}

static void count_free(void *ctx, void *ptr)
{
    counter_t *c = ctx;
    block_t *b;

    if (ptr == NULL)
        return;
    b = (block_t *)ptr - 1;
    c->live -= b->size;
    free(b);
}

static void test_adversarial_fit(void)
{
    size_t len, error_at;
    unsigned char *fit = adversarial_fit(&len, 65536);
    counter_t counter = {0, 0, 0};
    fwh_image_t *image = NULL;
    double start = seconds(), elapsed;
    int status;

    status = fwh_open(fit, len, 0, FWH_FMT_FIT, count_alloc, count_free, &counter, &image, &error_at);
    if (status == FWH_OK)
        fwh_audit(image);
    fwh_image_destroy(image);
    elapsed = seconds() - start;
    printf("adversarial fit: %zu bytes, status %s, %.2f ms, %zu allocations, peak %zu bytes\n", len,
           fwh_strerror(status), elapsed * 1000, counter.calls, counter.peak);
    EXPECT(elapsed < 0.050);
    EXPECT(counter.peak <= FWH_TEST_FIT_CEILING);
    EXPECT(counter.live == 0);
    free(fit);
}

static size_t calls_for(const unsigned char *buf, size_t len)
{
    counter_t counter = {0, 0, 0};
    fwh_image_t *image = NULL;
    size_t error_at;

    if (fwh_open(buf, len, 0, FWH_FMT_NONE, count_alloc, count_free, &counter, &image, &error_at) == FWH_OK)
        fwh_audit(image);
    fwh_image_destroy(image);
    return counter.calls;
}

static void test_allocation_constant(void)
{
    static const char *const fixed[] = {"baseline.bin", "exposed.bin", "netgear_chk.bin"};
    size_t i, len, big_len = 64u << 20;
    unsigned char *buf, *big;

    for (i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        if ((buf = load(fixed[i], &len)) == NULL || (big = calloc(1, big_len)) == NULL) {
            failures++;
            free(buf);
            continue;
        }
        memcpy(big, buf, len);
        EXPECT(calls_for(buf, len) == calls_for(big, big_len));
        free(big);
        free(buf);
    }
}

static void test_crc_against_zlib(void)
{
#ifdef FWH_TEST_ZLIB
    unsigned char *buf = malloc(65536);
    unsigned long seed = 12345;
    size_t i, j, len;

    for (i = 0; i < 10000 && buf; i++) {
        seed = seed * 6364136223846793005u + 1442695040888963407u;
        len = (size_t)(seed >> 33) % 65537;
        for (j = 0; j < len; j++) {
            seed = seed * 6364136223846793005u + 1442695040888963407u;
            buf[j] = (unsigned char)(seed >> 56);
        }
        EXPECT(fwh_crc32(0, buf, len) == (uint32_t)crc32(0, buf, (uInt)len));
    }
    free(buf);
#endif
}

int main(void)
{
#ifndef _WIN32
    test_guard_page();
#endif
    test_adversarial_fit();
    test_allocation_constant();
    test_crc_against_zlib();
    if (failures)
        fprintf(stderr, "%d failures\n", failures);
    return failures ? 1 : 0;
}
