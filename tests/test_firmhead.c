#include "firmhead/firmhead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

typedef struct {
    const char *file;
    size_t offset;
    int format;
    size_t parts;
    int checks_ok;
    size_t findings;
} sample_t;

static const sample_t samples[] = {
    {"baseline.bin", 0, FWH_FMT_UIMAGE, 1, 1, 0},
    {"exposed.bin", 0, FWH_FMT_TRX, 2, 1, 0},
    {"damaged.bin", 0, FWH_FMT_UIMAGE, 1, 0, 0},
    {"nested.bin", 0, FWH_FMT_FIT, 2, 1, 0},
    {"signed_weak.bin", 0, FWH_FMT_FIT, 2, 1, 2},
    {"signed_images_only.bin", 0, FWH_FMT_FIT, 2, 1, 1},
    {"signed_well.bin", 0, FWH_FMT_FIT, 2, 1, 0},
    {"tplink_safeloader.bin", 0, FWH_FMT_SAFELOADER, 3, 1, 1},
    {"xiaomi_hdr1.bin", 0, FWH_FMT_HDR1, 3, 1, 0},
    {"mikrotik_npk.bin", 0, FWH_FMT_NPK, 3, 1, 0},
    {"netgear_chk.bin", 0, FWH_FMT_CHK, 2, 1, 0},
    {"reolink_pak.bin", 0, FWH_FMT_PAK, 2, 1, 0},
    {"fwtool_signed.bin", 0x113, FWH_FMT_FWTOOL, 1, 1, 0},
    {"fwtool_placeholder.bin", 0xe7, FWH_FMT_FWTOOL, 1, 1, 0},
    {"uimage_multi.bin", 0, FWH_FMT_UIMAGE, 3, 1, 0},
    {"trx_v2.bin", 0, FWH_FMT_TRX, 3, 1, 0},
    {"fit_external.bin", 0, FWH_FMT_FIT, 2, 1, 0},
    {"fit_ambiguous.bin", 0, FWH_FMT_FIT, 2, 1, 3},
    {"safeloader_salted.bin", 0, FWH_FMT_SAFELOADER, 3, 1, 1},
    {"android_v0.bin", 0, FWH_FMT_ANDROID, 3, 1, 0},
    {"android_v2.bin", 0, FWH_FMT_ANDROID, 5, 1, 0},
    {"seama.bin", 0x30, FWH_FMT_SEAMA, 1, 1, 0},
    {"tplink_v1.bin", 0, FWH_FMT_TPLINK, 2, 1, 0},
    {"ubnt.bin", 0, FWH_FMT_UBNT, 2, 1, 0},
    {"ubnt_signed.bin", 0, FWH_FMT_UBNT, 3, 1, 0},
    {"mkimage/weak-hash.itb", 0, FWH_FMT_FIT, 2, 1, 1},
    {"mkimage/weak-hash.control.dtb", 0, FWH_FMT_DTB, 0, 1, 1},
    {"mkimage/images-only.itb", 0, FWH_FMT_FIT, 2, 1, 1},
    {"mkimage/images-only.control.dtb", 0, FWH_FMT_DTB, 0, 1, 0},
    {"mkimage/partial.itb", 0, FWH_FMT_FIT, 2, 1, 1},
    {"mkimage/partial.control.dtb", 0, FWH_FMT_DTB, 0, 1, 0},
    {"mkimage/optional-key.itb", 0, FWH_FMT_FIT, 2, 1, 0},
    {"mkimage/optional-key.control.dtb", 0, FWH_FMT_DTB, 0, 1, 1},
    {"mkimage/unit-address.itb", 0, FWH_FMT_FIT, 2, 1, 1},
    {"mkimage/unit-address.control.dtb", 0, FWH_FMT_DTB, 0, 1, 0},
    {"mkimage/good-2048.itb", 0, FWH_FMT_FIT, 2, 1, 0},
    {"mkimage/good-2048.control.dtb", 0, FWH_FMT_DTB, 0, 1, 0},
    {"mkimage/good-4096.itb", 0, FWH_FMT_FIT, 2, 1, 0},
    {"mkimage/good-4096.control.dtb", 0, FWH_FMT_DTB, 0, 1, 0},
};

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

static int all_ok(const fwh_image_t *image)
{
    size_t i;

    for (i = 0; i < fwh_checksum_count(image); i++)
        if (fwh_checksum_get(image, i)->state == FWH_CHECK_BAD)
            return 0;
    return 1;
}

static void hex(const unsigned char *d, size_t n, char *out)
{
    size_t i;

    for (i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", d[i]);
}

static void test_vectors(void)
{
    static const struct {
        const char *algo;
        const char *input;
        const char *digest;
    } v[] = {
        {"md5", "", "d41d8cd98f00b204e9800998ecf8427e"},
        {"md5", "a", "0cc175b9c0f1b6a831c399e269772661"},
        {"md5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"md5", "message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"md5", "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {"md5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"md5", "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "57edf4a22be3c955ac49da2e2107b67a"},
        {"sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"sha256", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"sha384", "abc",
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
        {"sha512", "abc",
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce"
         "80e2a9ac94fa54ca49f"},
        {"crc32", "123456789", "cbf43926"},
    };
    unsigned char digest[FWH_DIGEST_MAX];
    char text[2 * FWH_DIGEST_MAX + 1];
    size_t i, len;

    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        EXPECT(fwh_digest(v[i].algo, (const unsigned char *)v[i].input, strlen(v[i].input), digest, &len) == FWH_OK);
        hex(digest, len, text);
        EXPECT(strcmp(text, v[i].digest) == 0);
    }
    EXPECT(fwh_crc32(0, (const unsigned char *)"123456789", 9) == 0xCBF43926u);
    EXPECT(fwh_crc32(fwh_crc32(0, (const unsigned char *)"1234", 4), (const unsigned char *)"56789", 5) ==
           0xCBF43926u);
    EXPECT(fwh_digest("whirlpool", (const unsigned char *)"", 0, digest, &len) != FWH_OK);
}

static void test_sample(const sample_t *s, const unsigned char *buf, size_t len)
{
    fwh_image_t *image = NULL;
    size_t error_at = 0;
    uint64_t formats = 0;

    EXPECT(fwh_probe(buf, len, s->offset, &formats) == FWH_OK);
    EXPECT(formats & FWH_FMT_BIT(s->format));
    EXPECT(fwh_open(buf, len, s->offset, FWH_FMT_NONE, NULL, &image, &error_at) == FWH_OK);
    if (image == NULL)
        return;
    EXPECT(fwh_image_format(image) == s->format);
    EXPECT(fwh_part_count(image) == s->parts);
    EXPECT(all_ok(image) == s->checks_ok);
    EXPECT(fwh_audit(image) == FWH_OK);
    EXPECT(fwh_finding_count(image) == s->findings);
    EXPECT(fwh_image_description(image) != NULL);
    fwh_image_destroy(image);
}

static void test_truncation(const sample_t *s, const unsigned char *buf, size_t len)
{
    size_t cut, error_at, step = len > 4096 ? len / 997 : 1;
    fwh_image_t *image;
    unsigned char *copy;
    int status;

    for (cut = 0; cut < len; cut += step) {
        if ((copy = malloc(cut ? cut : 1)) == NULL)
            return;
        memcpy(copy, buf, cut);
        image = NULL;
        status = fwh_open(copy, cut, s->offset, s->format, NULL, &image, &error_at);
        EXPECT(status == FWH_OK || image == NULL);
        if (status == FWH_OK) {
            EXPECT(fwh_image_offset(image) + fwh_image_size(image) <= cut);
            fwh_audit(image);
        }
        fwh_image_destroy(image);
        free(copy);
    }
}

static size_t ok_count(const fwh_image_t *image)
{
    size_t i, n = 0;

    for (i = 0; i < fwh_checksum_count(image); i++)
        n += fwh_checksum_get(image, i)->state == FWH_CHECK_OK;
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

static void test_tamper(const sample_t *s, const unsigned char *buf, size_t len)
{
    size_t i, error_at, step = len > 1000 ? len / 1000 : 1;
    unsigned char *copy = malloc(len);
    fwh_image_t *original = NULL, *image;

    if (copy == NULL || fwh_open(buf, len, s->offset, s->format, NULL, &original, &error_at) != FWH_OK)
        goto done;
    for (i = 0; i < len; i += step) {
        if (!covered(original, i))
            continue;
        memcpy(copy, buf, len);
        copy[i] ^= 0x01;
        image = NULL;
        if (fwh_open(copy, len, s->offset, s->format, NULL, &image, &error_at) == FWH_OK &&
            ok_count(image) == ok_count(original)) {
            fprintf(stderr, "%s: flip at 0x%zx not detected\n", s->file, i);
            failures++;
        }
        fwh_image_destroy(image);
    }
done:
    fwh_image_destroy(original);
    free(copy);
}

typedef struct {
    size_t allowed;
    size_t used;
} budget_t;

static void *limited_alloc(void *ctx, size_t size)
{
    budget_t *b = ctx;

    if (b->used >= b->allowed)
        return NULL;
    b->used++;
    return malloc(size);
}

static void limited_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

static void test_alloc_failure(const sample_t *s, const unsigned char *buf, size_t len)
{
    budget_t budget;
    fwh_allocator_t allocator;
    fwh_image_t *image;
    size_t error_at;
    int status;

    allocator.alloc = limited_alloc;
    allocator.free = limited_free;
    allocator.ctx = &budget;
    for (budget.allowed = 0; budget.allowed < 10000; budget.allowed++) {
        budget.used = 0;
        image = NULL;
        status = fwh_open(buf, len, s->offset, s->format, &allocator, &image, &error_at);
        if (status == FWH_OK) {
            status = fwh_audit(image);
            if (status == FWH_ERR_NOMEM) {
                fwh_image_destroy(image);
                continue;
            }
            EXPECT(status == FWH_OK);
            fwh_image_destroy(image);
            return;
        }
        EXPECT(status == FWH_ERR_NOMEM);
        EXPECT(image == NULL);
    }
    EXPECT(!"allocation budget never sufficed");
}

static void test_arguments(void)
{
    fwh_image_t *image = (fwh_image_t *)&image;
    uint64_t formats;
    size_t error_at;
    unsigned char zero[64] = {0};

    EXPECT(fwh_open(NULL, 10, 0, FWH_FMT_NONE, NULL, &image, &error_at) == FWH_ERR_ARG);
    EXPECT(fwh_open(zero, sizeof(zero), 0, FWH_FMT_NONE, NULL, &image, &error_at) == FWH_ERR_FORMAT);
    EXPECT(image == NULL);
    EXPECT(fwh_open(zero, sizeof(zero), 65, FWH_FMT_NONE, NULL, &image, &error_at) == FWH_ERR_TRUNCATED);
    EXPECT(fwh_open(zero, sizeof(zero), 0, 99, NULL, &image, &error_at) == FWH_ERR_ARG);
    EXPECT(strcmp(fwh_version(), FWH_VERSION_STRING) == 0);
    EXPECT(fwh_format_from_name("ubnt") == FWH_FMT_UBNT);
    EXPECT(fwh_format_from_name("none") == FWH_FMT_NONE && fwh_format_from_name(NULL) == FWH_FMT_NONE);
    EXPECT(fwh_probe(zero, sizeof(zero), 0, &formats) == FWH_OK && formats == 0);
    EXPECT(fwh_audit(NULL) == FWH_ERR_ARG);
    fwh_image_destroy(NULL);
    EXPECT(fwh_part_get(NULL, 0) == NULL);
    EXPECT(strcmp(fwh_strerror(FWH_ERR_TRUNCATED), "unknown") != 0);
    EXPECT(strcmp(fwh_format_name(FWH_FMT_FIT), "fit") == 0);
}

static void test_signature_regions(void)
{
    size_t len, error_at;
    unsigned char *buf = load("fwtool_signed.bin", &len);
    fwh_image_t *image = NULL;
    const fwh_signature_t *s;

    if (buf == NULL || fwh_open(buf, len, len - 16, FWH_FMT_FWTOOL, NULL, &image, &error_at) != FWH_OK ||
        fwh_signature_count(image) != 1) {
        failures++;
    } else {
        s = fwh_signature_get(image, 0);
        if (s->signed_offset != 0 || s->signed_size != s->value_offset ||
            s->value_offset + s->value_size + 16 != len || strcmp(s->key_hint, "usign key 0123456789abcdef") != 0) {
            fprintf(stderr, "fwtool signature region or key wrong\n");
            failures++;
        }
    }
    fwh_image_destroy(image);
    free(buf);
}

static void test_part_find(void)
{
    size_t len, error_at;
    unsigned char *buf = load("android_v2.bin", &len);
    fwh_image_t *image = NULL;

    EXPECT(buf != NULL && fwh_open(buf, len, 0, FWH_FMT_NONE, NULL, &image, &error_at) == FWH_OK);
    EXPECT(fwh_part_find(image, "dtb") == fwh_part_get(image, 4));
    EXPECT(fwh_part_find(image, "missing") == NULL);
    EXPECT(fwh_part_find(NULL, "dtb") == NULL);
    fwh_image_destroy(image);
    free(buf);
}

int main(void)
{
    size_t i, len;
    unsigned char *buf;

    test_vectors();
    test_arguments();
    test_signature_regions();
    test_part_find();
    for (i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        if ((buf = load(samples[i].file, &len)) == NULL) {
            fprintf(stderr, "missing %s\n", samples[i].file);
            failures++;
            continue;
        }
        test_sample(&samples[i], buf, len);
        test_truncation(&samples[i], buf, len);
        test_tamper(&samples[i], buf, len);
        test_alloc_failure(&samples[i], buf, len);
        free(buf);
    }
    if (failures)
        fprintf(stderr, "%d failures\n", failures);
    return failures ? 1 : 0;
}
