#include "internal.h"

#include <string.h>

#define FWH_ABOOT_V0_HEADER 1632
#define FWH_ABOOT_V3_PAGE 4096
#define FWH_SEAMA_HEADER 12
#define FWH_SEAMA_DIGEST 16

typedef struct {
    unsigned version;
    uint32_t page;
    uint32_t sizes[5];
    const char *names[5];
    int roles[5];
    size_t count;
} fwh_aboot_t;

static uint64_t fwh_align(uint64_t value, uint32_t page)
{
    return (value + page - 1) / page * page;
}

static int fwh_aboot_read(const unsigned char *h, size_t avail, fwh_aboot_t *b)
{
    uint32_t page;

    if (avail < FWH_ABOOT_V0_HEADER || memcmp(h, "ANDROID!", 8) != 0)
        return 0;
    b->version = fwh_u32le(h + 40);
    if (b->version > 4 || (b->version == 1 && avail < 1648) || (b->version == 2 && avail < 1660))
        return 0;
    if (b->version >= 3) {
        b->page = FWH_ABOOT_V3_PAGE;
        b->sizes[0] = fwh_u32le(h + 8);
        b->sizes[1] = fwh_u32le(h + 12);
        b->sizes[2] = b->version == 4 ? fwh_u32le(h + 1580) : 0;
        b->names[2] = "boot_signature";
        b->roles[2] = FWH_ROLE_SIGNATURE;
        b->count = 3;
    } else {
        page = fwh_u32le(h + 36);
        if (page < 2048 || page > 16384 || (page & (page - 1)) != 0)
            return 0;
        b->page = page;
        b->sizes[0] = fwh_u32le(h + 8);
        b->sizes[1] = fwh_u32le(h + 16);
        b->sizes[2] = fwh_u32le(h + 24);
        b->sizes[3] = b->version >= 1 ? fwh_u32le(h + 1632) : 0;
        b->sizes[4] = b->version >= 2 ? fwh_u32le(h + 1648) : 0;
        b->names[2] = "second";
        b->roles[2] = FWH_ROLE_OTHER;
        b->names[3] = "recovery_dtbo";
        b->roles[3] = FWH_ROLE_FDT;
        b->names[4] = "dtb";
        b->roles[4] = FWH_ROLE_FDT;
        b->count = 3 + (b->version >= 1) + (b->version >= 2);
    }
    b->names[0] = "kernel";
    b->roles[0] = FWH_ROLE_KERNEL;
    b->names[1] = "ramdisk";
    b->roles[1] = FWH_ROLE_RAMDISK;
    return b->sizes[0] != 0;
}

static uint64_t fwh_aboot_end(const fwh_aboot_t *b)
{
    uint64_t at = b->page;
    size_t i;

    for (i = 0; i < b->count; i++)
        at += fwh_align(b->sizes[i], b->page);
    return at;
}

FWH_INTERNAL int fwh_probe_android(const unsigned char *buf, size_t buf_len, size_t offset)
{
    fwh_aboot_t b;

    return fwh_aboot_read(buf + offset, buf_len - offset, &b) && fwh_aboot_end(&b) <= buf_len - offset;
}

static int fwh_aboot_id(fwh_image_t *image, size_t offset, const fwh_aboot_t *b, const uint64_t *at)
{
    const unsigned char *h = image->buf + offset;
    const unsigned char *data[10];
    unsigned char sizes[5][4], digest[32];
    size_t lens[10], i, n = 0;
    fwh_checksum_t *check;
    static const unsigned char zero[32];

    for (i = 0; i < b->count; i++) {
        sizes[i][0] = (unsigned char)b->sizes[i];
        sizes[i][1] = (unsigned char)(b->sizes[i] >> 8);
        sizes[i][2] = (unsigned char)(b->sizes[i] >> 16);
        sizes[i][3] = (unsigned char)(b->sizes[i] >> 24);
        data[n] = image->buf + at[i];
        lens[n++] = b->sizes[i];
        data[n] = sizes[i];
        lens[n++] = 4;
    }
    if ((check = fwh_add_check(image, "sha1", FWH_SCOPE_DATA, "", offset + b->page, fwh_aboot_end(b) - b->page)) == NULL)
        return FWH_ERR_NOMEM;
    check->digest_len = 20;
    memcpy(check->expected, h + 576, 20);
    fwh_digest_parts("sha1", data, lens, n, digest);
    memcpy(check->computed, digest, 20);
    if (memcmp(digest, h + 576, 20) == 0 && memcmp(h + 596, zero, 12) == 0) {
        check->state = FWH_CHECK_OK;
        return FWH_OK;
    }
    fwh_digest_parts("sha256", data, lens, n, digest);
    if (memcmp(digest, h + 576, 32) == 0) {
        check->algorithm = "sha256";
        check->digest_len = 32;
        memcpy(check->expected, h + 576, 32);
        memcpy(check->computed, digest, 32);
        check->state = FWH_CHECK_OK;
        return FWH_OK;
    }
    check->state = FWH_CHECK_UNVERIFIABLE;
    return FWH_OK;
}

static int fwh_aboot_meta(fwh_image_t *image, const char *key, const unsigned char *text, size_t limit)
{
    return text[0] ? fwh_add_meta(image, key, fwh_ctext(image, text, limit)) : FWH_OK;
}

FWH_INTERNAL int fwh_parse_android(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    fwh_aboot_t b;
    uint64_t at[5], next;
    size_t i;

    if (!fwh_aboot_read(h, image->buf_len - offset, &b))
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    if (fwh_aboot_end(&b) > image->buf_len - offset)
        return fwh_fail(image, FWH_ERR_TRUNCATED, offset);
    next = offset + b.page;
    for (i = 0; i < b.count; i++) {
        at[i] = next;
        next += fwh_align(b.sizes[i], b.page);
        if (b.sizes[i] && fwh_add_part(image, b.names[i], at[i], b.sizes[i], b.roles[i]) == NULL)
            return FWH_ERR_NOMEM;
    }
    image->size = fwh_aboot_end(&b);
    image->description = fwh_printf(image, "Android boot image v%u, page %u", b.version, (unsigned)b.page);
    if (image->description == NULL || fwh_aboot_meta(image, "cmdline", h + (b.version >= 3 ? 44 : 64), 512) ||
        (b.version < 3 && fwh_aboot_meta(image, "name", h + 48, 16)))
        return FWH_ERR_NOMEM;
    return b.version < 3 ? fwh_aboot_id(image, offset, &b, at) : FWH_OK;
}

static uint64_t fwh_seama_head(uint32_t size)
{
    return FWH_SEAMA_HEADER + (size ? FWH_SEAMA_DIGEST : 0);
}

static int fwh_seama_read(const unsigned char *buf, size_t buf_len, size_t offset, uint32_t *meta, uint32_t *size)
{
    const unsigned char *h = buf + offset;

    if (buf_len - offset < FWH_SEAMA_HEADER || fwh_u32be(h) != 0x5EA3A417 || h[4] || h[5])
        return 0;
    *meta = (uint32_t)h[6] << 8 | h[7];
    *size = fwh_u32be(h + 8);
    return fwh_seama_head(*size) + *meta + *size <= buf_len - offset;
}

FWH_INTERNAL int fwh_probe_seama(const unsigned char *buf, size_t buf_len, size_t offset)
{
    uint32_t meta, size;

    return fwh_seama_read(buf, buf_len, offset, &meta, &size);
}

static int fwh_seama_meta(fwh_image_t *image, const unsigned char *text, size_t len)
{
    const unsigned char *eq = memchr(text, '=', len);

    if (eq == NULL || eq == text)
        return fwh_add_meta(image, "meta", fwh_text(image, text, len));
    return fwh_add_meta(image, fwh_text(image, text, (size_t)(eq - text)),
                        fwh_text(image, eq + 1, len - (size_t)(eq - text) - 1));
}

FWH_INTERNAL int fwh_parse_seama(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    uint32_t meta, size;
    size_t at, end, start;
    fwh_checksum_t *check;

    if (!fwh_seama_read(image->buf, image->buf_len, offset, &meta, &size))
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    start = offset + (size_t)fwh_seama_head(size) + meta;
    image->size = fwh_seama_head(size) + meta + size;
    image->description = size ? "SEAMA image" : "SEAMA envelope";
    for (at = start - meta; at < start; at = end + 1) {
        for (end = at; end < start && image->buf[end]; end++)
            ;
        if (end > at && fwh_seama_meta(image, image->buf + at, end - at))
            return FWH_ERR_NOMEM;
    }
    if (size == 0)
        return FWH_OK;
    if (fwh_add_part(image, "payload", start, size, FWH_ROLE_FIRMWARE) == NULL ||
        (check = fwh_add_check(image, "md5", FWH_SCOPE_DATA, "payload", start, size)) == NULL)
        return FWH_ERR_NOMEM;
    check->digest_len = 16;
    memcpy(check->expected, h + 12, 16);
    fwh_digest("md5", image->buf + start, size, check->computed, NULL);
    check->state = memcmp(check->expected, check->computed, 16) == 0 ? FWH_CHECK_OK : FWH_CHECK_BAD;
    return FWH_OK;
}
