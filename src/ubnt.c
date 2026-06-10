#include "internal.h"

#include <string.h>

#define FWH_UBNT_HEADER 0x104
#define FWH_UBNT_FIRST 0x10c
#define FWH_UBNT_PART 56
#define FWH_UBNT_TAIL 8
#define FWH_UBNT_END 12
#define FWH_UBNT_RSA 256

static int fwh_ubnt_magic(const unsigned char *h)
{
    return memcmp(h, "OPEN", 4) == 0 || memcmp(h, "UBNT", 4) == 0;
}

static size_t fwh_ubnt_walk(const unsigned char *buf, size_t buf_len, size_t offset, size_t *out_parts)
{
    size_t at = offset + FWH_UBNT_FIRST, count = 0;
    uint32_t size;

    if (buf_len - offset < FWH_UBNT_FIRST + FWH_UBNT_END || !fwh_ubnt_magic(buf + offset))
        return 0;
    while (buf_len - at >= FWH_UBNT_PART && memcmp(buf + at, "PART", 4) == 0) {
        size = fwh_u32be(buf + at + 48);
        if (size > buf_len - at - FWH_UBNT_PART || buf_len - at - FWH_UBNT_PART - size < FWH_UBNT_TAIL)
            return 0;
        at += FWH_UBNT_PART + size + FWH_UBNT_TAIL;
        count++;
    }
    if (count == 0 || buf_len - at < FWH_UBNT_END || (memcmp(buf + at, "END.", 4) && memcmp(buf + at, "ENDS", 4)))
        return 0;
    if (buf[at + 3] == 'S' && buf_len - at < 4 + FWH_UBNT_RSA + 4)
        return 0;
    if (out_parts)
        *out_parts = count;
    return at;
}

FWH_INTERNAL int fwh_probe_ubnt(const unsigned char *buf, size_t buf_len, size_t offset)
{
    return fwh_ubnt_walk(buf, buf_len, offset, NULL) != 0;
}

static int fwh_ubnt_crc(fwh_image_t *image, const char *covers, int scope, size_t from, size_t len, uint32_t expected)
{
    fwh_checksum_t *check = fwh_add_check(image, "crc32", scope, covers, from, len);

    if (check == NULL)
        return FWH_ERR_NOMEM;
    fwh_check_u32(check, expected, fwh_crc32(0, image->buf + from, len), 0);
    return FWH_OK;
}

static int fwh_ubnt_parts(fwh_image_t *image, size_t offset, size_t end)
{
    const unsigned char *b = image->buf;
    size_t at = offset + FWH_UBNT_FIRST;
    const char *name;
    uint32_t size;

    while (at < end) {
        size = fwh_u32be(b + at + 48);
        name = fwh_ctext(image, b + at + 4, 16);
        if (name == NULL ||
            fwh_add_part(image, name, at + FWH_UBNT_PART, size,
                         strcmp(name, "kernel") == 0   ? FWH_ROLE_KERNEL
                         : strcmp(name, "rootfs") == 0 ? FWH_ROLE_ROOTFS
                                                       : FWH_ROLE_FIRMWARE) == NULL ||
            fwh_ubnt_crc(image, name, FWH_SCOPE_PART, at, FWH_UBNT_PART + size,
                         fwh_u32be(b + at + FWH_UBNT_PART + size)))
            return FWH_ERR_NOMEM;
        at += FWH_UBNT_PART + size + FWH_UBNT_TAIL;
    }
    return FWH_OK;
}

static int fwh_ubnt_rsa(fwh_image_t *image, size_t offset, size_t end)
{
    static const unsigned char zero[FWH_UBNT_RSA];
    fwh_signature_t *sig;

    if (memcmp(image->buf + end + 4, zero, FWH_UBNT_RSA) == 0)
        return fwh_add_meta(image, "signature", "empty slot");
    if ((sig = fwh_add_sig(image, "ubnt/signature", "rsa2048", FWH_SCOPE_WHOLE, "whole image")) == NULL ||
        fwh_add_part(image, "signature", end + 4, FWH_UBNT_RSA, FWH_ROLE_SIGNATURE) == NULL)
        return FWH_ERR_NOMEM;
    sig->bits = 2048;
    sig->value_offset = end + 4;
    sig->value_size = FWH_UBNT_RSA;
    sig->signed_offset = offset;
    sig->signed_size = end - offset;
    return FWH_OK;
}

FWH_INTERNAL int fwh_parse_ubnt(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    size_t count = 0, end = fwh_ubnt_walk(image->buf, image->buf_len, offset, &count);
    int is_signed;

    if (end == 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    is_signed = image->buf[end + 3] == 'S';
    image->size = end - offset + (is_signed ? 4 + FWH_UBNT_RSA + 4 : FWH_UBNT_END);
    image->description = fwh_printf(image, "Ubiquiti %.4s, %zu partitions", (const char *)h, count);
    if (image->description == NULL || fwh_add_meta(image, "version", fwh_ctext(image, h + 4, 256)) ||
        fwh_ubnt_crc(image, "", FWH_SCOPE_HEADER, offset, FWH_UBNT_HEADER, fwh_u32be(h + FWH_UBNT_HEADER)) ||
        fwh_ubnt_parts(image, offset, end))
        return FWH_ERR_NOMEM;
    if (is_signed)
        return fwh_ubnt_rsa(image, offset, end);
    return fwh_ubnt_crc(image, "", FWH_SCOPE_WHOLE, offset, end - offset, fwh_u32be(image->buf + end + 4));
}
