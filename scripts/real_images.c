#define _POSIX_C_SOURCE 200809L
#include "firmhead/firmhead.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct { size_t offset; int format; } hit_t;

static int failures;

static unsigned char *load(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;

    if (f == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(*len);
    if (fread(buf, 1, *len, f) != *len)
        exit(2);
    fclose(f);
    return buf;
}

static size_t find(const unsigned char *buf, size_t len, hit_t *hits, size_t max)
{
    size_t off, n = 0, err;
    uint64_t formats;
    int fmt;
    fwh_image_t *image;

    for (off = 0; off < len && n < max; off++) {
        if (fwh_probe(buf, len, off, &formats) != FWH_OK || formats == 0)
            continue;
        for (fmt = 1; fmt < FWH_FMT_COUNT && n < max; fmt++) {
            image = NULL;
            if ((formats & FWH_FMT_BIT(fmt)) && fwh_open(buf, len, off, fmt, 0, NULL, &image, &err) == FWH_OK) {
                hits[n].offset = off;
                hits[n++].format = fmt;
            }
            fwh_image_destroy(image);
        }
    }
    return n;
}

static int state_of(const unsigned char *buf, size_t len, hit_t h, size_t index)
{
    fwh_image_t *image = NULL;
    size_t err;
    int state = -1;

    if (fwh_open(buf, len, h.offset, h.format, 0, NULL, &image, &err) == FWH_OK &&
        index < fwh_checksum_count(image))
        state = fwh_checksum_get(image, index)->state;
    fwh_image_destroy(image);
    return state;
}

static size_t ok_count(const unsigned char *buf, size_t len, hit_t h, fwh_image_t **keep)
{
    fwh_image_t *image = NULL;
    size_t err, i, n = 0;

    if (fwh_open(buf, len, h.offset, h.format, 0, NULL, &image, &err) == FWH_OK)
        for (i = 0; i < fwh_checksum_count(image); i++)
            n += fwh_checksum_get(image, i)->state == FWH_CHECK_OK;
    if (keep)
        *keep = image;
    else
        fwh_image_destroy(image);
    return n;
}

static int in_part(const fwh_image_t *image, size_t at)
{
    size_t i;

    for (i = 0; i < fwh_part_count(image); i++) {
        const fwh_part_t *p = fwh_part_get(image, i);

        if (at >= p->offset && at - p->offset < p->size)
            return 1;
    }
    return 0;
}

static int covered(const fwh_image_t *image, size_t at)
{
    size_t i;

    if (fwh_image_format(image) == FWH_FMT_ANDROID && !in_part(image, at))
        return 0;

    for (i = 0; i < fwh_checksum_count(image); i++) {
        const fwh_checksum_t *c = fwh_checksum_get(image, i);

        if (c->state == FWH_CHECK_OK && at >= c->offset && at - c->offset < c->size)
            return 1;
    }
    return 0;
}

static void tamper(const char *name, unsigned char *buf, size_t len, hit_t h)
{
    fwh_image_t *image = NULL;
    unsigned long long seed = 0x5EEDu;
    size_t base = ok_count(buf, len, h, &image), flips = 0, tries = 0, at, i;

    for (i = 0; i < fwh_checksum_count(image); i++)
        if (fwh_checksum_get(image, i)->state != FWH_CHECK_OK)
            printf("  %s %s: %s\n", fwh_checksum_get(image, i)->algorithm, fwh_checksum_get(image, i)->covers,
                   fwh_check_name(fwh_checksum_get(image, i)->state));
    while (base && flips < 1000 && tries < 10000000) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        at = (size_t)((seed >> 16) % len);
        tries++;
        if (!covered(image, at))
            continue;
        buf[at] ^= 0x01;
        if (ok_count(buf, len, h, NULL) >= base) {
            printf("FAIL %s flip at 0x%zx not detected\n", name, at);
            failures++;
        }
        buf[at] ^= 0x01;
        flips++;
    }
    printf("  %s@0x%zx: %zu checks ok, %zu flips\n", fwh_format_name(h.format), h.offset, base, flips);
    fwh_image_destroy(image);
}

static void truncate_all(const unsigned char *buf, size_t len, hit_t h)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE), limit, span, cut, err;
    unsigned char *map;
    fwh_image_t *image;

    if (h.offset > 0x10000)
        return;
    limit = len < h.offset + 0x4000 ? len : h.offset + 0x4000;
    span = (limit + page - 1) / page * page;
    map = mmap(NULL, span + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map + span, page, PROT_NONE) != 0)
        exit(3);
    for (cut = 0; cut <= limit; cut++) {
        unsigned char *start = map + span - cut;

        memcpy(start, buf, cut);
        image = NULL;
        if (fwh_open(start, cut, h.offset, h.format, 0, NULL, &image, &err) == FWH_OK)
            fwh_audit(image);
        fwh_image_destroy(image);
    }
    munmap(map, span + page);
}

int main(int argc, char **argv)
{
    hit_t hits[64];
    size_t len, n, i;
    int a;

    for (a = 1; a < argc; a++) {
        unsigned char *buf = load(argv[a], &len);

        n = find(buf, len, hits, 64);
        printf("%s: %zu images\n", argv[a], n);
        if (n == 0) {
            printf("FAIL nothing opened\n");
            failures++;
        }
        for (i = 0; i < n; i++) {
            tamper(argv[a], buf, len, hits[i]);
            truncate_all(buf, len, hits[i]);
        }
        free(buf);
    }
    printf("%d failures\n", failures);
    return failures != 0;
}
