#include "firmhead/firmhead.h"
#include "internal.h"

#include <string.h>

#define FWH_UIMAGE_HEADER 64
#define FWH_UIMAGE_MULTI 4
#define FWH_UIMAGE_PARTS 256

static const char *const fwh_uimage_os[] = {
    "invalid", "openbsd", "netbsd", "freebsd", "4.4bsd",   "linux", "svr4",    "esix",    "solaris", "irix",
    "sco",     "dell",    "ncr",    "lynxos",  "vxworks",  "psos",  "qnx",     "u-boot",  "rtems",   "artos",
    "unity",   "integrity", "ose",  "plan9",   "openrtos", "arm-trusted-firmware", "tee", "opensbi", "efi"};
static const char *const fwh_uimage_arch[] = {
    "invalid", "alpha", "arm",     "x86",     "ia64",   "mips",  "mips64", "powerpc", "s390",
    "sh",      "sparc", "sparc64", "m68k",    "nios",   "microblaze", "nios2", "blackfin", "avr32",
    "st200",   "sandbox", "nds32", "openrisc", "arm64", "arc",   "x86_64", "xtensa",  "riscv"};
static const char *const fwh_uimage_type[] = {
    "invalid", "standalone", "kernel", "ramdisk", "multi", "firmware", "script", "filesystem", "flat_dt",
    "kwbimage", "imximage", "ublimage", "omapimage", "aisimage", "kernel_noload"};
static const char *const fwh_uimage_comp[] = {"none", "gzip", "bzip2", "lzma", "lzo", "lz4", "zstd"};
static const int fwh_uimage_roles[] = {FWH_ROLE_OTHER,    FWH_ROLE_FIRMWARE, FWH_ROLE_KERNEL, FWH_ROLE_RAMDISK,
                                       FWH_ROLE_OTHER,    FWH_ROLE_FIRMWARE, FWH_ROLE_SCRIPT, FWH_ROLE_ROOTFS,
                                       FWH_ROLE_FDT};

#define FWH_LABEL(table, value)                                                             \
    ((size_t)(value) < sizeof(table) / sizeof(table[0]) ? fwh_text(image, table[value], strlen(table[value])) \
                                                         : fwh_printf(image, "unknown %u", (unsigned)(value)))

static int fwh_uimage_header_ok(const unsigned char *h)
{
    unsigned char copy[FWH_UIMAGE_HEADER];

    memcpy(copy, h, sizeof(copy));
    memset(copy + 4, 0, 4);
    return fwh_crc32(0, copy, sizeof(copy)) == fwh_u32be(h + 4);
}

FWH_INTERNAL int fwh_probe_uimage(const unsigned char *buf, size_t buf_len, size_t offset)
{
    const unsigned char *h = buf + offset;

    if (buf_len - offset < FWH_UIMAGE_HEADER || fwh_u32be(h) != 0x27051956)
        return 0;
    return fwh_uimage_header_ok(h) && fwh_u32be(h + 12) <= buf_len - offset - FWH_UIMAGE_HEADER;
}

static int fwh_uimage_role(unsigned type)
{
    if (type == 14)
        return FWH_ROLE_KERNEL;
    return type < sizeof(fwh_uimage_roles) / sizeof(fwh_uimage_roles[0]) ? fwh_uimage_roles[type] : FWH_ROLE_OTHER;
}

static int fwh_uimage_multi(fwh_image_t *image, size_t data, uint32_t data_size, const char *comp)
{
    size_t count = 0, table, position;
    fwh_part_t *part;

    while (1) {
        if (count * 4 + 4 > data_size)
            return fwh_fail(image, FWH_ERR_TRUNCATED, data + count * 4);
        if (fwh_u32be(image->buf + data + count * 4) == 0)
            break;
        if (++count > FWH_UIMAGE_PARTS)
            return fwh_fail(image, FWH_ERR_LIMIT, data);
    }
    table = count * 4 + 4;
    position = table;
    for (size_t i = 0; i < count; i++) {
        uint32_t size = fwh_u32be(image->buf + data + i * 4);

        if (size > data_size - position)
            return fwh_fail(image, FWH_ERR_TRUNCATED, data + i * 4);
        part = fwh_add_part(image, fwh_printf(image, "part@%zu", i), data + position, size, FWH_ROLE_OTHER);
        if (part == NULL)
            return FWH_ERR_NOMEM;
        part->compression = comp;
        position = (position + size + 3) & ~(size_t)3;
        if (position > data_size)
            position = data_size;
    }
    return FWH_OK;
}

static int fwh_uimage_meta(fwh_image_t *image, const unsigned char *h)
{
    int status = FWH_OK;

    status |= fwh_add_meta(image, "name", fwh_ctext(image, h + 32, 32));
    status |= fwh_add_meta(image, "os", FWH_LABEL(fwh_uimage_os, h[28]));
    status |= fwh_add_meta(image, "arch", FWH_LABEL(fwh_uimage_arch, h[29]));
    status |= fwh_add_meta(image, "type", FWH_LABEL(fwh_uimage_type, h[30]));
    status |= fwh_add_meta(image, "compression", FWH_LABEL(fwh_uimage_comp, h[31]));
    status |= fwh_add_meta(image, "load", fwh_printf(image, "0x%08x", (unsigned)fwh_u32be(h + 16)));
    status |= fwh_add_meta(image, "entry", fwh_printf(image, "0x%08x", (unsigned)fwh_u32be(h + 20)));
    status |= fwh_add_meta(image, "time", fwh_printf(image, "%u", (unsigned)fwh_u32be(h + 8)));
    return status ? FWH_ERR_NOMEM : FWH_OK;
}

FWH_INTERNAL int fwh_parse_uimage(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    size_t data = offset + FWH_UIMAGE_HEADER;
    uint32_t size;
    fwh_checksum_t *check;
    fwh_part_t *part;
    const char *comp;

    if (!fwh_has(image, offset, FWH_UIMAGE_HEADER) || fwh_u32be(h) != 0x27051956)
        return fwh_fail(image, fwh_has(image, offset, 4) ? FWH_ERR_FORMAT : FWH_ERR_TRUNCATED, offset);
    if (!fwh_uimage_header_ok(h))
        return fwh_fail(image, FWH_ERR_DAMAGED, offset + 4);
    size = fwh_u32be(h + 12);
    if (!fwh_has(image, data, size))
        return fwh_fail(image, FWH_ERR_TRUNCATED, offset + 12);
    image->size = FWH_UIMAGE_HEADER + (uint64_t)size;
    if (fwh_uimage_meta(image, h) != FWH_OK)
        return FWH_ERR_NOMEM;
    comp = fwh_meta_find(image, "compression");
    image->description = fwh_printf(image, "\"%s\", %s, %s, %s, %s", fwh_meta_find(image, "name"),
                                    fwh_meta_find(image, "os"), fwh_meta_find(image, "arch"),
                                    fwh_meta_find(image, "type"), comp);
    check = fwh_add_check(image, "crc32", FWH_SCOPE_DATA, "", data, size);
    if (check == NULL || image->description == NULL)
        return FWH_ERR_NOMEM;
    fwh_check_u32(check, fwh_u32be(h + 24), fwh_crc32(0, image->buf + data, size), 0);
    if (h[30] == FWH_UIMAGE_MULTI)
        return fwh_uimage_multi(image, data, size, comp);
    part = fwh_add_part(image, fwh_meta_find(image, "type"), data, size, fwh_uimage_role(h[30]));
    if (part == NULL)
        return FWH_ERR_NOMEM;
    part->compression = comp;
    return FWH_OK;
}

static int fwh_trx_read(const unsigned char *buf, size_t buf_len, size_t offset, uint32_t *offsets, int *out_count)
{
    const unsigned char *h = buf + offset;
    uint32_t length, previous = 0;
    int version, count, i, used = 0;
    size_t header;

    if (buf_len - offset < 28 || memcmp(h, "HDR0", 4) != 0)
        return 0;
    version = fwh_u16le(h + 14);
    if (version != 1 && version != 2)
        return 0;
    count = version == 1 ? 3 : 4;
    header = 16 + 4 * (size_t)count;
    length = fwh_u32le(h + 4);
    if (buf_len - offset < header || length <= header || length > buf_len - offset)
        return 0;
    for (i = 0; i < count; i++) {
        offsets[i] = fwh_u32le(h + 16 + 4 * i);
        if (offsets[i] == 0)
            continue;
        if (offsets[i] < header || offsets[i] >= length || offsets[i] < previous)
            return 0;
        previous = offsets[i];
        used++;
    }
    *out_count = count;
    return used > 0;
}

FWH_INTERNAL int fwh_probe_trx(const unsigned char *buf, size_t buf_len, size_t offset)
{
    uint32_t offsets[4];
    int count;

    return fwh_trx_read(buf, buf_len, offset, offsets, &count);
}

FWH_INTERNAL int fwh_parse_trx(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    uint32_t offsets[4], length, end;
    int count, i, j, used = 0;
    fwh_checksum_t *check;

    if (!fwh_trx_read(image->buf, image->buf_len, offset, offsets, &count))
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    length = fwh_u32le(h + 4);
    image->size = length;
    check = fwh_add_check(image, "crc32", FWH_SCOPE_WHOLE, "", offset + 12, length - 12);
    if (check == NULL)
        return FWH_ERR_NOMEM;
    fwh_check_u32(check, fwh_u32le(h + 8), fwh_crc32(0, h + 12, length - 12), 1);
    for (i = 0; i < count; i++) {
        if (offsets[i] == 0)
            continue;
        end = length;
        for (j = i + 1; j < count; j++)
            if (offsets[j]) {
                end = offsets[j];
                break;
            }
        if (fwh_add_part(image, fwh_printf(image, "part@%d", i), offset + offsets[i], end - offsets[i],
                         FWH_ROLE_OTHER) == NULL)
            return FWH_ERR_NOMEM;
        used++;
    }
    image->description = fwh_printf(image, "v%u, %d partitions", (unsigned)fwh_u16le(h + 14), used);
    if (fwh_add_meta(image, "version", fwh_printf(image, "%u", (unsigned)fwh_u16le(h + 14))) ||
        fwh_add_meta(image, "flags", fwh_printf(image, "0x%04x", (unsigned)fwh_u16le(h + 12))))
        return FWH_ERR_NOMEM;
    return image->description ? FWH_OK : FWH_ERR_NOMEM;
}

#define FWH_FWTOOL_TRAILER 16
#define FWH_FWTOOL_LIMIT (1u << 20)

static int fwh_fwtool_read(const unsigned char *buf, size_t buf_len, size_t offset, int *out_kind, uint32_t *out_size)
{
    const unsigned char *t = buf + offset;
    uint32_t size;

    if (buf_len - offset < FWH_FWTOOL_TRAILER || memcmp(t, "FWx0", 4) != 0)
        return 0;
    size = fwh_u32be(t + 12);
    if (t[8] > 1 || size <= FWH_FWTOOL_TRAILER || size > FWH_FWTOOL_LIMIT || size > offset + FWH_FWTOOL_TRAILER)
        return 0;
    *out_kind = t[8];
    *out_size = size;
    return 1;
}

FWH_INTERNAL int fwh_probe_fwtool(const unsigned char *buf, size_t buf_len, size_t offset)
{
    int kind;
    uint32_t size;

    return fwh_fwtool_read(buf, buf_len, offset, &kind, &size);
}

FWH_INTERNAL int fwh_parse_fwtool(fwh_image_t *image, size_t offset)
{
    static const char placeholder[] = "# fake certificate";
    int kind;
    uint32_t size;
    size_t start, data_len;
    const unsigned char *data;
    fwh_signature_t *sig;

    if (!fwh_fwtool_read(image->buf, image->buf_len, offset, &kind, &size))
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    start = offset + FWH_FWTOOL_TRAILER - size;
    data = image->buf + start;
    data_len = size - FWH_FWTOOL_TRAILER;
    image->offset = start;
    image->size = size;
    if (kind == 1) {
        image->description = "OpenWrt image metadata";
        if (fwh_add_part(image, "metadata", start, data_len, FWH_ROLE_METADATA) == NULL ||
            fwh_add_meta(image, "metadata", fwh_text(image, data, data_len)))
            return FWH_ERR_NOMEM;
        return FWH_OK;
    }
    if (fwh_add_part(image, "signature", start, data_len, FWH_ROLE_SIGNATURE) == NULL)
        return FWH_ERR_NOMEM;
    if (data_len >= sizeof(placeholder) - 1 && memcmp(data, placeholder, sizeof(placeholder) - 1) == 0) {
        image->description = "signature placeholder (fake certificate)";
        return fwh_add_meta(image, "integrity", "fwtool placeholder signature");
    }
    image->description = "usign/ucert signature";
    sig = fwh_add_sig(image, "fwtool/signature", "usign ed25519", FWH_SCOPE_WHOLE, "whole image");
    if (sig == NULL)
        return FWH_ERR_NOMEM;
    sig->bits = 256;
    return fwh_add_meta(image, "integrity", "fwtool");
}

#define FWH_CHK_FIXED 40

static int fwh_chk_read(const unsigned char *buf, size_t buf_len, size_t offset, uint32_t *header, size_t *board_len)
{
    const unsigned char *h = buf + offset;
    uint64_t kernel, rootfs;
    size_t i;

    if (buf_len - offset < FWH_CHK_FIXED || memcmp(h, "*#$^", 4) != 0)
        return 0;
    *header = fwh_u32be(h + 4);
    kernel = fwh_u32be(h + 24);
    rootfs = fwh_u32be(h + 28);
    if (*header <= FWH_CHK_FIXED || *header > 256 || kernel + rootfs == 0 ||
        *header + kernel + rootfs > buf_len - offset)
        return 0;
    for (i = FWH_CHK_FIXED; i < *header && h[i] != 0; i++)
        if (h[i] < 32 || h[i] > 126)
            return 0;
    *board_len = i - FWH_CHK_FIXED;
    return *board_len > 0;
}

FWH_INTERNAL int fwh_probe_chk(const unsigned char *buf, size_t buf_len, size_t offset)
{
    uint32_t header;
    size_t board_len;

    return fwh_chk_read(buf, buf_len, offset, &header, &board_len);
}

static int fwh_chk_sum(fwh_image_t *image, const char *covers, size_t start, size_t size, uint32_t expected,
                       uint32_t computed)
{
    fwh_checksum_t *check = fwh_add_check(image, "netgear", FWH_SCOPE_PART, covers, start, size);

    if (check == NULL)
        return FWH_ERR_NOMEM;
    fwh_check_u32(check, expected, computed, 0);
    if (expected == 0)
        check->state = FWH_CHECK_UNVERIFIABLE;
    return FWH_OK;
}

static uint32_t fwh_chk_header_sum(const unsigned char *h, uint32_t header)
{
    unsigned char copy[256];

    memcpy(copy, h, header);
    memset(copy + 36, 0, 4);
    return fwh_netgear_sum(copy, header);
}

FWH_INTERNAL int fwh_parse_chk(fwh_image_t *image, size_t offset)
{
    const unsigned char *h = image->buf + offset;
    uint32_t header, kernel, rootfs;
    size_t board_len, k, r;
    int status = FWH_OK;

    if (!fwh_chk_read(image->buf, image->buf_len, offset, &header, &board_len))
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    kernel = fwh_u32be(h + 24);
    rootfs = fwh_u32be(h + 28);
    k = offset + header;
    r = k + kernel;
    image->size = (uint64_t)header + kernel + rootfs;
    image->description = fwh_printf(image, "board %.*s", (int)board_len, (const char *)h + FWH_CHK_FIXED);
    if (image->description == NULL || fwh_add_meta(image, "board", fwh_text(image, h + FWH_CHK_FIXED, board_len)))
        return FWH_ERR_NOMEM;
    if ((kernel && fwh_add_part(image, "kernel", k, kernel, FWH_ROLE_KERNEL) == NULL) ||
        (rootfs && fwh_add_part(image, "rootfs", r, rootfs, FWH_ROLE_ROOTFS) == NULL))
        return FWH_ERR_NOMEM;
    status |= fwh_chk_sum(image, "header", offset, header, fwh_u32be(h + 36), fwh_chk_header_sum(h, header));
    status |= fwh_chk_sum(image, "kernel", k, kernel, fwh_u32be(h + 16), fwh_netgear_sum(image->buf + k, kernel));
    status |= fwh_chk_sum(image, "rootfs", r, rootfs, fwh_u32be(h + 20), fwh_netgear_sum(image->buf + r, rootfs));
    status |= fwh_chk_sum(image, "image", k, (size_t)kernel + rootfs, fwh_u32be(h + 32),
                          fwh_netgear_sum(image->buf + k, (size_t)kernel + rootfs));
    return status ? FWH_ERR_NOMEM : FWH_OK;
}

#define FWH_PAK_TABLE 0x0C
#define FWH_PAK_ENTRY 0x40
#define FWH_PAK_ENTRIES 32

static int fwh_pak_walk(const unsigned char *buf, size_t buf_len, size_t offset, fwh_image_t *image, uint64_t *out_end)
{
    const unsigned char *h = buf + offset;
    uint64_t expected, start, size;
    size_t entry, i, name_len;
    int named = 0;

    if (buf_len - offset < FWH_PAK_TABLE + FWH_PAK_ENTRY || fwh_u32be(h) != 0x13597232)
        return -1;
    expected = fwh_u32le(h + FWH_PAK_TABLE + 0x38);
    if (expected < FWH_PAK_TABLE + FWH_PAK_ENTRY)
        return -1;
    *out_end = expected;
    for (i = 0; i < FWH_PAK_ENTRIES; i++) {
        entry = FWH_PAK_TABLE + i * FWH_PAK_ENTRY;
        if (entry + FWH_PAK_ENTRY > buf_len - offset || entry + FWH_PAK_ENTRY > expected)
            break;
        start = fwh_u32le(h + entry + 0x38);
        size = fwh_u32le(h + entry + 0x3C);
        if (start != expected)
            break;
        for (name_len = 0; name_len < 32 && h[entry + name_len]; name_len++)
            if (h[entry + name_len] > 127)
                return -1;
        if (start + size > buf_len - offset)
            return -1;
        expected = start + size;
        *out_end = expected;
        if (name_len == 0 || size == 0)
            continue;
        named++;
        if (image && fwh_add_part(image, fwh_text(image, h + entry, name_len), offset + start, size,
                                  FWH_ROLE_OTHER) == NULL)
            return -2;
    }
    return named;
}

FWH_INTERNAL int fwh_probe_pak(const unsigned char *buf, size_t buf_len, size_t offset)
{
    uint64_t end;

    return fwh_pak_walk(buf, buf_len, offset, NULL, &end) > 0;
}

FWH_INTERNAL int fwh_parse_pak(fwh_image_t *image, size_t offset)
{
    uint64_t end = 0;
    int named = fwh_pak_walk(image->buf, image->buf_len, offset, image, &end);
    fwh_checksum_t *check;
    uint32_t computed;

    if (named == -2)
        return FWH_ERR_NOMEM;
    if (named <= 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    image->size = end;
    image->description = fwh_join_parts(image, 0, -1);
    check = fwh_add_check(image, "crc32", FWH_SCOPE_WHOLE, "", offset + FWH_PAK_TABLE, end - FWH_PAK_TABLE);
    if (check == NULL || image->description == NULL)
        return FWH_ERR_NOMEM;
    computed = fwh_crc32(0, image->buf + offset + FWH_PAK_TABLE, (size_t)end - FWH_PAK_TABLE);
    fwh_check_u32(check, fwh_u32le(image->buf + offset + 4), computed, 0);
    if (check->state == FWH_CHECK_BAD)
        check->state = FWH_CHECK_UNVERIFIABLE;
    return FWH_OK;
}
