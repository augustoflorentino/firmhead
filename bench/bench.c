#define _POSIX_C_SOURCE 200809L
#include "firmhead/firmhead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int compare(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;

    return x < y ? -1 : x > y;
}

static void fill(unsigned char *buf, size_t len)
{
    unsigned long seed = 99;
    size_t i;

    for (i = 0; i < len; i++) {
        seed = seed * 6364136223846793005u + 1442695040888963407u;
        buf[i] = (unsigned char)(seed >> 56);
    }
}

static void bench_probe(const unsigned char *buf, size_t len)
{
    double runs[31];
    uint64_t formats, sink = 0;
    size_t r, i, n = 1u << 20;

    for (r = 0; r < 31; r++) {
        double start = now();

        for (i = 0; i < n; i++) {
            fwh_probe(buf, len, i * 7 % (len - 4096), &formats);
            sink += formats;
        }
        runs[r] = (now() - start) / (double)n * 1e9;
    }
    qsort(runs, 31, sizeof(double), compare);
    printf("probe       %8.1f ns median (sink %llu)\n", runs[15], (unsigned long long)sink);
}

static void bench_digest(const char *algo, const unsigned char *buf, size_t len)
{
    unsigned char out[FWH_DIGEST_MAX];
    double best = 1e9;
    size_t out_len;
    int r;

    for (r = 0; r < 5; r++) {
        double start = now();

        fwh_digest(algo, buf, len, out, &out_len);
        if (now() - start < best)
            best = now() - start;
    }
    printf("%-11s %8.0f MB/s\n", algo, (double)len / best / 1e6);
}

static void put_be(unsigned char *p, unsigned long v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static void bench_open(unsigned char *buf, size_t len)
{
    unsigned char header[64];
    fwh_image_t *image;
    size_t error_at;
    double best = 1e9;
    int r;

    memset(header, 0, sizeof(header));
    put_be(header, 0x27051956);
    put_be(header + 12, (unsigned long)(len - 64));
    put_be(header + 24, (unsigned long)fwh_crc32(0, buf + 64, len - 64));
    header[28] = 5;
    header[29] = 5;
    header[30] = 2;
    memcpy(header + 32, "bench", 5);
    put_be(header + 4, (unsigned long)fwh_crc32(0, header, 64));
    memcpy(buf, header, 64);
    for (r = 0; r < 5; r++) {
        double start = now();

        if (fwh_open(buf, len, 0, FWH_FMT_NONE, 0, NULL, &image, &error_at) != FWH_OK)
            return;
        fwh_audit(image);
        if (now() - start < best)
            best = now() - start;
        fwh_image_destroy(image);
    }
    printf("open 8 MiB  %8.2f ms (uImage, crc32 over the payload)\n", best * 1000);
}

int main(void)
{
    size_t len = 8u << 20;
    unsigned char *buf = malloc(len);

    if (buf == NULL)
        return 1;
    fill(buf, len);
    bench_probe(buf, len);
    bench_digest("crc32", buf, len);
    bench_digest("md5", buf, len);
    bench_digest("sha1", buf, len);
    bench_digest("sha256", buf, len);
    bench_digest("sha512", buf, len);
    bench_open(buf, len);
    free(buf);
    return 0;
}
