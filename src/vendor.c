#include "firmhead/firmhead.h"
#include "internal.h"

#include <string.h>

#define FWH_SL_TABLE 0x1014
#define FWH_SL_TABLE_SIZE 0x800
#define FWH_SL_SIG_START 0x130
#define FWH_SL_SIG_END 0x1D0
#define FWH_SL_PARTS 32

static const unsigned char fwh_sl_salt[16] = {0x7a, 0x2b, 0x15, 0xed, 0x9b, 0x98, 0x59, 0x6d,
                                              0xe5, 0x04, 0xab, 0x44, 0xac, 0x2a, 0x9f, 0x4e};

typedef struct {
    size_t name_at;
    size_t name_len;
    uint64_t start;
    uint64_t size;
} fwh_sl_part_t;

static int fwh_is_word(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
           c == '-';
}

static size_t fwh_hex(const unsigned char *p, size_t limit, uint64_t *out)
{
    size_t n = 0;
    uint64_t value = 0;

    while (n < limit && n < 8) {
        unsigned char c = p[n];
        int digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                                     : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (digit < 0)
            break;
        value = value * 16 + (uint64_t)digit;
        n++;
    }
    *out = value;
    return n;
}

static size_t fwh_expect(const unsigned char *t, size_t at, size_t len, const char *word)
{
    size_t n = strlen(word);

    return at + n <= len && memcmp(t + at, word, n) == 0 ? at + n : 0;
}

static size_t fwh_sl_entry(const unsigned char *t, size_t at, size_t len, fwh_sl_part_t *part)
{
    size_t i = fwh_expect(t, at, len, "fwup-ptn "), n;

    if (i == 0)
        return 0;
    part->name_at = i;
    while (i < len && fwh_is_word(t[i]) && i - part->name_at < 32)
        i++;
    part->name_len = i - part->name_at;
    if (part->name_len == 0 || (i = fwh_expect(t, i, len, " base 0x")) == 0)
        return 0;
    if ((n = fwh_hex(t + i, len - i, &part->start)) == 0 || (i = fwh_expect(t, i + n, len, " size 0x")) == 0)
        return 0;
    if ((n = fwh_hex(t + i, len - i, &part->size)) == 0)
        return 0;
    return i + n;
}

static int fwh_sl_parts(const unsigned char *buf, size_t buf_len, size_t offset, fwh_sl_part_t *parts)
{
    const unsigned char *t = buf + offset + FWH_SL_TABLE;
    size_t at = 0, next;
    uint64_t end;
    int count = 0, i;

    if (buf_len - offset < FWH_SL_TABLE + FWH_SL_TABLE_SIZE)
        return -1;
    end = buf_len - offset - FWH_SL_TABLE;
    while (at < FWH_SL_TABLE_SIZE && count < FWH_SL_PARTS) {
        next = fwh_sl_entry(t, at, FWH_SL_TABLE_SIZE, &parts[count]);
        if (next == 0) {
            at++;
            continue;
        }
        count++;
        at = next;
    }
    for (i = 0; i < count; i++)
        if (parts[i].size == 0 || parts[i].start + parts[i].size > end)
            return -1;
    return count;
}

FWH_INTERNAL int fwh_probe_safeloader(const unsigned char *buf, size_t buf_len, size_t offset)
{
    fwh_sl_part_t parts[FWH_SL_PARTS];
    uint32_t size;

    if (buf_len - offset < FWH_SL_TABLE + FWH_SL_TABLE_SIZE)
        return 0;
    size = fwh_u32be(buf + offset);
    if (size <= FWH_SL_TABLE || size > buf_len - offset)
        return 0;
    return fwh_sl_parts(buf, buf_len, offset, parts) > 0;
}

static int fwh_sl_check(fwh_image_t *image, size_t offset, uint32_t size)
{
    const unsigned char *h = image->buf + offset;
    fwh_checksum_t *check = fwh_add_check(image, "md5", FWH_SCOPE_WHOLE, "", offset + 0x14, size - 0x14);
    unsigned char digest[16];

    if (check == NULL)
        return FWH_ERR_NOMEM;
    check->digest_len = 16;
    memcpy(check->expected, h + 4, 16);
    fwh_digest2("md5", fwh_sl_salt, 16, h + 0x14, size - 0x14, digest, NULL);
    if (memcmp(digest, h + 4, 16) == 0) {
        check->algorithm = "md5+salt";
    } else {
        fwh_digest2("md5", NULL, 0, h + 0x14, size - 0x14, digest, NULL);
    }
    memcpy(check->computed, digest, 16);
    check->state = memcmp(digest, h + 4, 16) == 0 ? FWH_CHECK_OK : FWH_CHECK_BAD;
    if (check->state == FWH_CHECK_BAD)
        check->algorithm = "md5+salt";
    return FWH_OK;
}

static int fwh_sl_signature(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    size_t length = FWH_SL_SIG_END - FWH_SL_SIG_START, rounded;
    fwh_signature_t *sig;

    if (h[FWH_SL_SIG_START - 0x1C] != 0xAA || h[FWH_SL_SIG_START - 0x1B] != 0x55)
        return FWH_OK;
    while (length > 0 && h[FWH_SL_SIG_START + length - 1] == 0)
        length--;
    if (length == 0)
        return FWH_OK;
    rounded = length <= 64 ? 64 : length <= 128 ? 128 : 256;
    if (rounded > FWH_SL_SIG_END - FWH_SL_SIG_START)
        rounded = FWH_SL_SIG_END - FWH_SL_SIG_START;
    sig = fwh_add_sig(image, "tplink/signature", fwh_printf(image, "rsa%zu", rounded * 8), FWH_SCOPE_WHOLE,
                      "whole image");
    if (sig == NULL)
        return FWH_ERR_NOMEM;
    sig->bits = (unsigned)(rounded * 8);
    sig->key_hint = "vendor area 0x130";
    return fwh_add_part(image, "signature", offset + FWH_SL_SIG_START, rounded, FWH_ROLE_SIGNATURE) ? FWH_OK
                                                                                                     : FWH_ERR_NOMEM;
}

FWH_INTERNAL int fwh_parse_safeloader(fwh_image_t *image, size_t offset)
{
    fwh_sl_part_t parts[FWH_SL_PARTS];
    const unsigned char *h = image->buf + offset;
    size_t base = offset + FWH_SL_TABLE, kind_len = 0;
    int count, i, status;

    if (!fwh_probe_safeloader(image->buf, image->buf_len, offset))
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    count = fwh_sl_parts(image->buf, image->buf_len, offset, parts);
    image->size = fwh_u32be(h);
    while (kind_len < 0x2C && h[0x14 + kind_len] != '\n' && h[0x14 + kind_len] != 0)
        kind_len++;
    if (kind_len)
        image->description = fwh_printf(image, "%.*s, %d partitions", (int)kind_len, (const char *)h + 0x14, count);
    else
        image->description = fwh_printf(image, "safeloader, %d partitions", count);
    if (image->description == NULL || fwh_add_meta(image, "fw-type", fwh_text(image, h + 0x14, kind_len)))
        return FWH_ERR_NOMEM;
    for (i = 0; i < count; i++) {
        const char *name = fwh_text(image, image->buf + base + parts[i].name_at, parts[i].name_len);

        if (fwh_add_part(image, name, base + parts[i].start, parts[i].size, FWH_ROLE_OTHER) == NULL)
            return FWH_ERR_NOMEM;
    }
    if ((status = fwh_sl_check(image, offset, (uint32_t)image->size)) != FWH_OK)
        return status;
    return fwh_sl_signature(image, offset);
}

#define FWH_HDR1_BLOBS 8
#define FWH_HDR1_BLOB_HEADER 48

static int fwh_hdr1_walk(const unsigned char *buf, size_t buf_len, size_t offset, fwh_image_t *image)
{
    const unsigned char *h = buf + offset;
    size_t avail = buf_len - offset, start;
    uint32_t sig_at, size;
    int i, count = 0;

    if (avail < 16 + 4 * FWH_HDR1_BLOBS || memcmp(h, "HDR1", 4) != 0)
        return -1;
    sig_at = fwh_u32le(h + 4);
    if (sig_at == 0 || sig_at >= avail)
        return -1;
    for (i = 0; i < FWH_HDR1_BLOBS; i++) {
        start = fwh_u32le(h + 16 + 4 * i);
        if (start == 0)
            continue;
        if (start > avail || avail - start < FWH_HDR1_BLOB_HEADER)
            return -1;
        size = fwh_u32le(h + start + 8);
        if (fwh_u32le(h + start) != 0xBABE || size == 0 || size > avail - start - FWH_HDR1_BLOB_HEADER)
            return -1;
        count++;
        if (image == NULL)
            continue;
        if (fwh_add_part(image, h[start + 16] ? fwh_ctext(image, h + start + 16, 32)
                                              : fwh_printf(image, "blob@0x%zx", start),
                         offset + start + FWH_HDR1_BLOB_HEADER, size, FWH_ROLE_OTHER) == NULL)
            return -2;
    }
    return count;
}

FWH_INTERNAL int fwh_probe_hdr1(const unsigned char *buf, size_t buf_len, size_t offset)
{
    return fwh_hdr1_walk(buf, buf_len, offset, NULL) > 0;
}

static int fwh_hdr1_signature(fwh_image_t *image, size_t at)
{
    uint32_t length;
    fwh_signature_t *sig;

    if (!fwh_has(image, at, 4))
        return FWH_OK;
    length = fwh_u32le(image->buf + at);
    if ((length != 128 && length != 256 && length != 384 && length != 512) || !fwh_has(image, at + 16, length))
        return FWH_OK;
    sig = fwh_add_sig(image, "xiaomi/signature", fwh_printf(image, "rsa%u", (unsigned)length * 8), FWH_SCOPE_WHOLE,
                      "whole image");
    if (sig == NULL)
        return FWH_ERR_NOMEM;
    sig->bits = length * 8;
    sig->key_hint = fwh_printf(image, "appended at 0x%zx", at);
    return fwh_add_part(image, "signature", at + 16, length, FWH_ROLE_SIGNATURE) ? FWH_OK : FWH_ERR_NOMEM;
}

FWH_INTERNAL int fwh_parse_hdr1(fwh_image_t *image, size_t offset)
{
    int count = fwh_hdr1_walk(image->buf, image->buf_len, offset, image);
    fwh_checksum_t *check;
    size_t body = offset + 12;

    if (count == -2)
        return FWH_ERR_NOMEM;
    if (count <= 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    image->size = image->buf_len - offset;
    image->description = fwh_printf(image, "HDR1, %s", fwh_join_parts(image, 0, FWH_ROLE_SIGNATURE));
    check = fwh_add_check(image, "crc32", FWH_SCOPE_WHOLE, "", body, image->buf_len - body);
    if (check == NULL)
        return FWH_ERR_NOMEM;
    fwh_check_u32(check, fwh_u32le(image->buf + offset + 8), fwh_crc32(0, image->buf + body, image->buf_len - body),
                  1);
    return fwh_hdr1_signature(image, offset + fwh_u32le(image->buf + offset + 4));
}

#define FWH_NPK_PARTS 64

static int fwh_npk_part(fwh_image_t *image, int kind, size_t start, uint32_t size)
{
    fwh_part_t *part;
    fwh_signature_t *sig;

    switch (kind) {
    case 1:
        return fwh_add_meta(image, "package", fwh_ctext(image, image->buf + start, size < 16 ? size : 16));
    case 21:
        return fwh_add_part(image, "squashfs", start, size, FWH_ROLE_ROOTFS) ? FWH_OK : FWH_ERR_NOMEM;
    case 7:
        return fwh_add_part(image, "script", start, size, FWH_ROLE_SCRIPT) ? FWH_OK : FWH_ERR_NOMEM;
    case 4:
        if ((part = fwh_add_part(image, "files", start, size, FWH_ROLE_FILES)) == NULL)
            return FWH_ERR_NOMEM;
        part->compression = "zlib";
        return FWH_OK;
    case 9:
        sig = fwh_add_sig(image, "npk/signature", fwh_printf(image, "vendor (%u bytes)", (unsigned)size),
                          FWH_SCOPE_WHOLE, "whole image");
        if (sig == NULL || fwh_add_part(image, "signature", start, size, FWH_ROLE_SIGNATURE) == NULL)
            return FWH_ERR_NOMEM;
        return FWH_OK;
    default:
        return FWH_OK;
    }
}

static int fwh_npk_walk(const unsigned char *buf, size_t buf_len, size_t offset, fwh_image_t *image)
{
    const unsigned char *h = buf + offset;
    uint64_t end, pos;
    uint32_t size;
    int kind, count = 0, known = 0;

    if (buf_len - offset < 8 || fwh_u32be(h) != 0x1ef1d0ba)
        return -1;
    end = 8 + (uint64_t)fwh_u32le(h + 4);
    if (end > buf_len - offset)
        return -1;
    for (pos = 8; pos + 6 <= end && count < FWH_NPK_PARTS; pos += 6 + size, count++) {
        kind = fwh_u16le(h + pos);
        size = fwh_u32le(h + pos + 2);
        if (size > end - pos - 6)
            return -1;
        known += kind == 21 || kind == 7 || kind == 4;
        if (image == NULL)
            continue;
        if (fwh_npk_part(image, kind, offset + pos + 6, size) != FWH_OK)
            return -2;
    }
    return known;
}

FWH_INTERNAL int fwh_probe_npk(const unsigned char *buf, size_t buf_len, size_t offset)
{
    return fwh_npk_walk(buf, buf_len, offset, NULL) > 0;
}

FWH_INTERNAL int fwh_parse_npk(fwh_image_t *image, size_t offset)
{
    int known = fwh_npk_walk(image->buf, image->buf_len, offset, image);

    if (known == -2)
        return FWH_ERR_NOMEM;
    if (known <= 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    image->size = 8 + (uint64_t)fwh_u32le(image->buf + offset + 4);
    image->description = fwh_printf(image, "RouterOS package, %s", fwh_join_parts(image, 0, FWH_ROLE_SIGNATURE));
    return image->description ? FWH_OK : FWH_ERR_NOMEM;
}
