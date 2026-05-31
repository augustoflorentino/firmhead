#include "firmhead/firmhead.h"
#include "internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FWH_CHUNK_SIZE 4096

struct fwh_chunk {
    fwh_chunk_t *next;
    size_t used;
    size_t cap;
};

static void *fwh_default_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void fwh_default_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

FWH_INTERNAL int fwh_fail(fwh_image_t *image, int status, size_t at)
{
    image->error_at = at;
    return status;
}

FWH_INTERNAL int fwh_has(const fwh_image_t *image, uint64_t offset, uint64_t size)
{
    return offset <= image->buf_len && size <= image->buf_len - offset;
}

FWH_INTERNAL uint32_t fwh_u32be(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

FWH_INTERNAL uint32_t fwh_u32le(const unsigned char *p)
{
    return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | (uint32_t)p[0];
}

FWH_INTERNAL uint16_t fwh_u16le(const unsigned char *p)
{
    return (uint16_t)(p[1] << 8 | p[0]);
}

static void *fwh_arena(fwh_image_t *image, size_t size)
{
    fwh_chunk_t *chunk = image->chunks;
    size_t cap;

    size = (size + 7) & ~(size_t)7;
    if (chunk == NULL || chunk->cap - chunk->used < size) {
        cap = size > FWH_CHUNK_SIZE ? size : FWH_CHUNK_SIZE;
        chunk = image->alloc_fn(image->alloc_ctx, sizeof(*chunk) + cap);
        if (chunk == NULL)
            return NULL;
        chunk->next = image->chunks;
        chunk->used = 0;
        chunk->cap = cap;
        image->chunks = chunk;
    }
    chunk->used += size;
    return (unsigned char *)(chunk + 1) + chunk->used - size;
}

FWH_INTERNAL void *fwh_scratch(fwh_image_t *image, size_t size)
{
    return fwh_arena(image, size);
}

FWH_INTERNAL const char *fwh_text(fwh_image_t *image, const void *data, size_t len)
{
    char *text;

    if (len > FWH_TEXT_LIMIT)
        len = FWH_TEXT_LIMIT;
    text = fwh_arena(image, len + 1);
    if (text == NULL)
        return NULL;
    if (len)
        memcpy(text, data, len);
    text[len] = '\0';
    return text;
}

FWH_INTERNAL const char *fwh_ctext(fwh_image_t *image, const unsigned char *data, size_t limit)
{
    size_t len = 0;

    while (len < limit && data[len] != 0)
        len++;
    return fwh_text(image, data, len);
}

FWH_INTERNAL const char *fwh_printf(fwh_image_t *image, const char *fmt, ...)
{
    char small[256], *text;
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(small, sizeof(small), fmt, ap);
    va_end(ap);
    if (n < 0)
        return NULL;
    if ((size_t)n < sizeof(small))
        return fwh_text(image, small, (size_t)n);
    if ((size_t)n > FWH_TEXT_LIMIT)
        n = FWH_TEXT_LIMIT;
    if ((text = fwh_arena(image, (size_t)n + 1)) == NULL)
        return NULL;
    va_start(ap, fmt);
    vsnprintf(text, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return text;
}

static void *fwh_push(fwh_image_t *image, fwh_list_t *list, size_t size)
{
    void *items;
    size_t cap;

    if (list->count >= FWH_LIST_LIMIT)
        return NULL;
    if (list->count == list->cap) {
        cap = list->cap ? list->cap * 2 : 8;
        items = image->alloc_fn(image->alloc_ctx, cap * size);
        if (items == NULL)
            return NULL;
        if (list->count)
            memcpy(items, list->items, list->count * size);
        if (list->items)
            image->free_fn(image->alloc_ctx, list->items);
        list->items = items;
        list->cap = cap;
    }
    items = (unsigned char *)list->items + list->count++ * size;
    memset(items, 0, size);
    return items;
}

FWH_INTERNAL const char *fwh_join_parts(fwh_image_t *image, size_t first, int skip_role)
{
    const fwh_part_t *parts = image->parts.items;
    char *text, *cursor;
    size_t i, total = 1;

    for (i = first; i < image->parts.count; i++)
        total += strlen(parts[i].name) + 2;
    if ((text = fwh_arena(image, total)) == NULL)
        return NULL;
    cursor = text;
    *cursor = '\0';
    for (i = first; i < image->parts.count; i++) {
        size_t len = strlen(parts[i].name);

        if (parts[i].role == skip_role)
            continue;
        if (cursor != text) {
            memcpy(cursor, ", ", 2);
            cursor += 2;
        }
        memcpy(cursor, parts[i].name, len + 1);
        cursor += len;
    }
    return text;
}

FWH_INTERNAL fwh_part_t *fwh_add_part(fwh_image_t *image, const char *name, uint64_t offset, uint64_t size, int role)
{
    fwh_part_t *part;

    if (name == NULL || (part = fwh_push(image, &image->parts, sizeof(*part))) == NULL)
        return NULL;
    part->name = name;
    part->offset = offset;
    part->size = size;
    part->role = role;
    part->compression = "";
    part->detail = "";
    return part;
}

FWH_INTERNAL int fwh_add_meta(fwh_image_t *image, const char *key, const char *value)
{
    fwh_meta_t *meta;

    if (value == NULL || (meta = fwh_push(image, &image->metas, sizeof(*meta))) == NULL)
        return FWH_ERR_NOMEM;
    meta->key = key;
    meta->value = value;
    return FWH_OK;
}

FWH_INTERNAL fwh_checksum_t *fwh_add_check(fwh_image_t *image, const char *algorithm, int scope, const char *covers,
                                           uint64_t offset, uint64_t size)
{
    fwh_checksum_t *check;

    if (covers == NULL || (check = fwh_push(image, &image->checks, sizeof(*check))) == NULL)
        return NULL;
    check->algorithm = algorithm;
    check->scope = scope;
    check->covers = covers;
    check->state = FWH_CHECK_UNVERIFIABLE;
    check->offset = offset;
    check->size = size;
    return check;
}

FWH_INTERNAL void fwh_check_u32(fwh_checksum_t *check, uint32_t expected, uint32_t computed, int accept_inverted)
{
    int i;

    for (i = 0; i < 4; i++) {
        check->expected[i] = (unsigned char)(expected >> (24 - 8 * i));
        check->computed[i] = (unsigned char)(computed >> (24 - 8 * i));
    }
    check->digest_len = 4;
    if (expected == computed || (accept_inverted && expected == (computed ^ 0xFFFFFFFFu)))
        check->state = FWH_CHECK_OK;
    else
        check->state = FWH_CHECK_BAD;
}

FWH_INTERNAL fwh_signature_t *fwh_add_sig(fwh_image_t *image, const char *node, const char *algorithm, int scope,
                                          const char *covers)
{
    fwh_signature_t *sig;

    if (node == NULL || algorithm == NULL || covers == NULL ||
        (sig = fwh_push(image, &image->sigs, sizeof(*sig))) == NULL)
        return NULL;
    sig->node = node;
    sig->algorithm = algorithm;
    sig->key_hint = "";
    sig->scope = scope;
    sig->covers = covers;
    sig->value_offset = sig->value_size = sig->signed_offset = sig->signed_size = 0;
    return sig;
}

FWH_INTERNAL fwh_key_t *fwh_add_key(fwh_image_t *image, const char *node)
{
    fwh_key_t *key;

    if (node == NULL || (key = fwh_push(image, &image->keys, sizeof(*key))) == NULL)
        return NULL;
    key->node = node;
    key->algorithm = "";
    key->key_hint = "";
    key->required = "";
    return key;
}

FWH_INTERNAL fwh_config_t *fwh_add_config(fwh_image_t *image, const char *name, const char *loads)
{
    fwh_config_t *config;

    if (name == NULL || loads == NULL || (config = fwh_push(image, &image->configs, sizeof(*config))) == NULL)
        return NULL;
    config->name = name;
    config->loads = loads;
    return config;
}

FWH_INTERNAL fwh_finding_t *fwh_add_finding(fwh_image_t *image, int code, const char *where, const char *evidence)
{
    fwh_finding_t *finding;

    if (where == NULL || evidence == NULL || (finding = fwh_push(image, &image->findings, sizeof(*finding))) == NULL)
        return NULL;
    finding->code = code;
    finding->where = where;
    finding->evidence = evidence;
    return finding;
}

static const unsigned char fwh_m_uimage[] = {0x27, 0x05, 0x19, 0x56};
static const unsigned char fwh_m_trx[] = {'H', 'D', 'R', '0'};
static const unsigned char fwh_m_fwtool[] = {'F', 'W', 'x', '0'};
static const unsigned char fwh_m_safeloader[] = {'f', 'w', 'u', 'p', '-', 'p', 't', 'n', ' '};
static const unsigned char fwh_m_hdr1[] = {'H', 'D', 'R', '1'};
static const unsigned char fwh_m_npk[] = {0x1e, 0xf1, 0xd0, 0xba};
static const unsigned char fwh_m_chk[] = {'*', '#', '$', '^'};
static const unsigned char fwh_m_pak[] = {0x13, 0x59, 0x72, 0x32};
static const unsigned char fwh_m_fdt[] = {0xd0, 0x0d, 0xfe, 0xed};
static const unsigned char fwh_m_android[] = {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'};
static const unsigned char fwh_m_seama[] = {0x5e, 0xa3, 0xa4, 0x17};
static const unsigned char fwh_m_tplink[] = {0x01, 0x00, 0x00, 0x00};

static const fwh_magic_t fwh_magic_table[] = {
    {FWH_FMT_UIMAGE, fwh_m_uimage, 4, 0},
    {FWH_FMT_TRX, fwh_m_trx, 4, 0},
    {FWH_FMT_FWTOOL, fwh_m_fwtool, 4, 0},
    {FWH_FMT_SAFELOADER, fwh_m_safeloader, 9, 0x1014},
    {FWH_FMT_HDR1, fwh_m_hdr1, 4, 0},
    {FWH_FMT_NPK, fwh_m_npk, 4, 0},
    {FWH_FMT_CHK, fwh_m_chk, 4, 0},
    {FWH_FMT_PAK, fwh_m_pak, 4, 0},
    {FWH_FMT_FIT, fwh_m_fdt, 4, 0},
    {FWH_FMT_DTB, fwh_m_fdt, 4, 0},
    {FWH_FMT_ANDROID, fwh_m_android, 8, 0},
    {FWH_FMT_SEAMA, fwh_m_seama, 4, 0},
    {FWH_FMT_TPLINK, fwh_m_tplink, 4, 0},
};

const fwh_magic_t *fwh_magics(size_t *out_count)
{
    if (out_count)
        *out_count = sizeof(fwh_magic_table) / sizeof(fwh_magic_table[0]);
    return fwh_magic_table;
}

static const fwh_parse_fn fwh_parsers[FWH_FMT_COUNT] = {
    NULL,           fwh_parse_uimage, fwh_parse_trx, fwh_parse_fwtool, fwh_parse_safeloader, fwh_parse_hdr1,
    fwh_parse_npk,  fwh_parse_chk,    fwh_parse_pak, fwh_parse_fit,    fwh_parse_dtb,    fwh_parse_android,
    fwh_parse_seama, fwh_parse_tplink,
};

int fwh_probe(const unsigned char *buf, size_t buf_len, size_t offset, unsigned *out_formats)
{
    unsigned mask = 0;
    int fdt;

    if (out_formats == NULL || (buf == NULL && buf_len))
        return FWH_ERR_ARG;
    *out_formats = 0;
    if (offset >= buf_len)
        return FWH_OK;
    if (fwh_probe_uimage(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_UIMAGE;
    if (fwh_probe_trx(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_TRX;
    if (fwh_probe_fwtool(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_FWTOOL;
    if (fwh_probe_safeloader(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_SAFELOADER;
    if (fwh_probe_hdr1(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_HDR1;
    if (fwh_probe_npk(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_NPK;
    if (fwh_probe_chk(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_CHK;
    if (fwh_probe_pak(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_PAK;
    if (fwh_probe_android(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_ANDROID;
    if (fwh_probe_seama(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_SEAMA;
    if (fwh_probe_tplink(buf, buf_len, offset))
        mask |= 1u << FWH_FMT_TPLINK;
    fdt = fwh_probe_fdt(buf, buf_len, offset);
    if (fdt)
        mask |= 1u << fdt;
    *out_formats = mask;
    return FWH_OK;
}

static void fwh_free_lists(fwh_image_t *image)
{
    fwh_list_t *lists[] = {&image->parts,   &image->metas,   &image->checks,  &image->sigs,
                           &image->keys,    &image->configs, &image->findings};
    size_t i;

    for (i = 0; i < sizeof(lists) / sizeof(lists[0]); i++)
        if (lists[i]->items)
            image->free_fn(image->alloc_ctx, lists[i]->items);
}

void fwh_image_destroy(fwh_image_t *image)
{
    fwh_chunk_t *chunk, *next;

    if (image == NULL)
        return;
    fwh_free_lists(image);
    for (chunk = image->chunks; chunk; chunk = next) {
        next = chunk->next;
        image->free_fn(image->alloc_ctx, chunk);
    }
    image->free_fn(image->alloc_ctx, image);
}

static int fwh_pick_format(const unsigned char *buf, size_t buf_len, size_t offset)
{
    unsigned mask = 0;
    int format;

    fwh_probe(buf, buf_len, offset, &mask);
    for (format = 1; format < FWH_FMT_COUNT; format++)
        if (mask & (1u << format))
            return format;
    return FWH_FMT_NONE;
}

int fwh_open(const unsigned char *buf, size_t buf_len, size_t offset, int format, const fwh_allocator_t *allocator,
             fwh_image_t **out_image, size_t *out_error_at)
{
    fwh_alloc_fn alloc_fn = allocator ? allocator->alloc : NULL;
    fwh_free_fn free_fn = allocator ? allocator->free : NULL;
    void *alloc_ctx = allocator ? allocator->ctx : NULL;
    fwh_image_t *image;
    int status;

    if (out_error_at)
        *out_error_at = offset;
    if (out_image == NULL || (buf == NULL && buf_len) || (alloc_fn == NULL) != (free_fn == NULL) || format < 0 ||
        format >= FWH_FMT_COUNT)
        return FWH_ERR_ARG;
    *out_image = NULL;
    if (offset >= buf_len)
        return FWH_ERR_TRUNCATED;
    if (format == FWH_FMT_NONE && (format = fwh_pick_format(buf, buf_len, offset)) == FWH_FMT_NONE)
        return FWH_ERR_FORMAT;
    if (alloc_fn == NULL) {
        alloc_fn = fwh_default_alloc;
        free_fn = fwh_default_free;
    }
    image = alloc_fn(alloc_ctx, sizeof(*image));
    if (image == NULL)
        return FWH_ERR_NOMEM;
    memset(image, 0, sizeof(*image));
    image->alloc_fn = alloc_fn;
    image->free_fn = free_fn;
    image->alloc_ctx = alloc_ctx;
    image->buf = buf;
    image->buf_len = buf_len;
    image->format = format;
    image->offset = offset;
    image->description = "";
    image->error_at = offset;
    status = fwh_parsers[format](image, offset);
    if (status != FWH_OK) {
        if (out_error_at)
            *out_error_at = image->error_at;
        fwh_image_destroy(image);
        return status;
    }
    *out_image = image;
    return FWH_OK;
}

int fwh_image_format(const fwh_image_t *image)
{
    return image ? image->format : FWH_FMT_NONE;
}

uint64_t fwh_image_offset(const fwh_image_t *image)
{
    return image ? image->offset : 0;
}

uint64_t fwh_image_size(const fwh_image_t *image)
{
    return image ? image->size : 0;
}

const char *fwh_image_description(const fwh_image_t *image)
{
    return image ? image->description : "";
}

int fwh_image_signed(const fwh_image_t *image)
{
    return image != NULL && image->sigs.count > 0;
}

#define FWH_ACCESSORS(name, type, list)                                         \
    size_t fwh_##name##_count(const fwh_image_t *image)                         \
    {                                                                           \
        return image ? image->list.count : 0;                                   \
    }                                                                           \
    const type *fwh_##name##_get(const fwh_image_t *image, size_t index)        \
    {                                                                           \
        if (image == NULL || index >= image->list.count)                        \
            return NULL;                                                        \
        return (const type *)image->list.items + index;                         \
    }

FWH_ACCESSORS(part, fwh_part_t, parts)
FWH_ACCESSORS(meta, fwh_meta_t, metas)
FWH_ACCESSORS(checksum, fwh_checksum_t, checks)
FWH_ACCESSORS(signature, fwh_signature_t, sigs)
FWH_ACCESSORS(key, fwh_key_t, keys)
FWH_ACCESSORS(config, fwh_config_t, configs)
FWH_ACCESSORS(finding, fwh_finding_t, findings)

const fwh_part_t *fwh_part_find(const fwh_image_t *image, const char *name)
{
    size_t i;

    if (image == NULL || name == NULL)
        return NULL;
    for (i = 0; i < image->parts.count; i++) {
        const fwh_part_t *part = (const fwh_part_t *)image->parts.items + i;

        if (strcmp(part->name, name) == 0)
            return part;
    }
    return NULL;
}

const char *fwh_meta_find(const fwh_image_t *image, const char *key)
{
    size_t i;

    if (image == NULL || key == NULL)
        return NULL;
    for (i = 0; i < image->metas.count; i++) {
        const fwh_meta_t *meta = (const fwh_meta_t *)image->metas.items + i;

        if (strcmp(meta->key, key) == 0)
            return meta->value;
    }
    return NULL;
}

static const char *fwh_pick(const char *const *names, size_t count, int index)
{
    return index >= 0 && (size_t)index < count && names[index] ? names[index] : "unknown";
}

#define FWH_PICK(table, index) fwh_pick(table, sizeof(table) / sizeof(table[0]), index)

const char *fwh_strerror(int status)
{
    static const char *const names[] = {"ok",
                                        "invalid argument",
                                        "out of memory",
                                        "not this format",
                                        "truncated: a declared size runs past the buffer",
                                        "damaged header: its own checksum fails",
                                        "limit reached: the input exceeds a fixed bound"};
    return FWH_PICK(names, status);
}

const char *fwh_version(void)
{
    return FWH_VERSION_STRING;
}

const char *fwh_format_name(int format)
{
    static const char *const names[] = {"none", "uimage", "trx", "fwtool", "safeloader", "hdr1",
                                        "npk",  "chk",    "pak", "fit",    "dtb",  "android", "seama", "tplink"};
    return FWH_PICK(names, format);
}

const char *fwh_role_name(int role)
{
    static const char *const names[] = {"other",    "kernel", "rootfs", "fdt",       "ramdisk",
                                        "firmware", "script", "files",  "signature", "metadata"};
    return FWH_PICK(names, role);
}

const char *fwh_scope_name(int scope)
{
    static const char *const names[] = {NULL, "header", "data", "part", "whole image", "image", "configuration"};
    return FWH_PICK(names, scope);
}

const char *fwh_check_name(int state)
{
    static const char *const names[] = {NULL, "ok", "bad", "unverifiable"};
    return FWH_PICK(names, state);
}

const char *fwh_finding_name(int code)
{
    static const char *const names[] = {NULL,
                                        "weak signature algorithm or key",
                                        "FIT signs images, not configurations",
                                        "signed configuration loads unsigned images",
                                        "verification keys present, none required",
                                        "ambiguous FIT node (unit address or duplicate name)"};
    return FWH_PICK(names, code);
}
