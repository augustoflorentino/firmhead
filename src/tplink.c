#include "internal.h"

#include <string.h>

#define FWH_TPV1_HEADER 0x200
#define FWH_TPV1_MD5 0x4c

static const unsigned char fwh_tpv1_salts[2][16] = {
    {0xdc, 0xd7, 0x3a, 0xa5, 0xc3, 0x95, 0x98, 0xfb, 0xdd, 0xf9, 0xe7, 0xf4, 0x0e, 0xae, 0x47, 0x38},
    {0x8c, 0xef, 0x33, 0x5b, 0xd5, 0xc5, 0xce, 0xfa, 0xa7, 0x9c, 0x28, 0xda, 0xb2, 0xe9, 0x0f, 0x42},
};

static int fwh_tpv1_inside(const unsigned char *h, size_t field, uint32_t total)
{
    uint32_t at = fwh_u32be(h + field), len = fwh_u32be(h + field + 4);

    return len == 0 || (at >= FWH_TPV1_HEADER && at <= total && len <= total - at);
}

static uint32_t fwh_tpv1_size(const unsigned char *buf, size_t buf_len, size_t offset)
{
    const unsigned char *h = buf + offset;
    uint32_t total;

    if (buf_len - offset < FWH_TPV1_HEADER || fwh_u32be(h) != 0x01000000u || h[4] < 0x20 || h[4] > 0x7e)
        return 0;
    total = fwh_u32be(h + 0x7c);
    if (total < FWH_TPV1_HEADER || total > buf_len - offset || fwh_u32be(h + 0x84) == 0)
        return 0;
    if (!fwh_tpv1_inside(h, 0x80, total) || !fwh_tpv1_inside(h, 0x88, total) || !fwh_tpv1_inside(h, 0x90, total))
        return 0;
    return total;
}

FWH_INTERNAL int fwh_probe_tplink(const unsigned char *buf, size_t buf_len, size_t offset)
{
    return fwh_tpv1_size(buf, buf_len, offset) != 0;
}

static int fwh_tpv1_check(fwh_image_t *image, size_t offset, uint32_t total)
{
    const unsigned char *h = image->buf + offset;
    fwh_checksum_t *check = fwh_add_check(image, "md5+salt", FWH_SCOPE_WHOLE, "", offset, total);
    size_t i;

    if (check == NULL)
        return FWH_ERR_NOMEM;
    check->digest_len = 16;
    memcpy(check->expected, h + FWH_TPV1_MD5, 16);
    check->state = FWH_CHECK_BAD;
    for (i = 0; i < 2; i++) {
        const unsigned char *data[3] = {h, fwh_tpv1_salts[i], h + FWH_TPV1_MD5 + 16};
        size_t lens[3] = {FWH_TPV1_MD5, 16, total - FWH_TPV1_MD5 - 16};

        fwh_digest_parts("md5", data, lens, 3, check->computed);
        if (memcmp(check->computed, check->expected, 16) == 0) {
            check->state = FWH_CHECK_OK;
            break;
        }
    }
    return FWH_OK;
}

static int fwh_tpv1_part(fwh_image_t *image, size_t offset, size_t field, const char *name, int role)
{
    const unsigned char *h = image->buf + offset;
    uint32_t len = fwh_u32be(h + field + 4);

    if (len == 0)
        return FWH_OK;
    return fwh_add_part(image, name, offset + fwh_u32be(h + field), len, role) ? FWH_OK : FWH_ERR_NOMEM;
}

FWH_INTERNAL int fwh_parse_tplink(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    uint32_t total = fwh_tpv1_size(image->buf, image->buf_len, offset);

    if (total == 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    image->size = total;
    image->description = fwh_printf(image, "TP-Link v1, hardware %08x rev %u", (unsigned)fwh_u32be(h + 0x40),
                                    (unsigned)fwh_u32be(h + 0x44));
    if (image->description == NULL || fwh_add_meta(image, "vendor", fwh_ctext(image, h + 4, 24)) ||
        fwh_add_meta(image, "version", fwh_ctext(image, h + 0x1c, 36)) ||
        fwh_add_meta(image, "hw_id", fwh_printf(image, "0x%08x", (unsigned)fwh_u32be(h + 0x40))) ||
        fwh_add_meta(image, "load", fwh_printf(image, "0x%08x", (unsigned)fwh_u32be(h + 0x74))) ||
        fwh_add_meta(image, "entry", fwh_printf(image, "0x%08x", (unsigned)fwh_u32be(h + 0x78))) ||
        fwh_tpv1_part(image, offset, 0x80, "kernel", FWH_ROLE_KERNEL) ||
        fwh_tpv1_part(image, offset, 0x88, "rootfs", FWH_ROLE_ROOTFS) ||
        fwh_tpv1_part(image, offset, 0x90, "bootloader", FWH_ROLE_FIRMWARE))
        return FWH_ERR_NOMEM;
    return fwh_tpv1_check(image, offset, total);
}
