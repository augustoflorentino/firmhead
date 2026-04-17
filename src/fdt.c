#include "firmhead/firmhead.h"
#include "internal.h"

#include <string.h>

#define FWH_FDT_MAGIC 0xD00DFEEDu
#define FWH_FDT_BEGIN 1
#define FWH_FDT_END_NODE 2
#define FWH_FDT_PROP 3
#define FWH_FDT_NOP 4
#define FWH_FDT_END 9
#define FWH_FDT_DEPTH 64
#define FWH_FDT_ITEMS 65536
#define FWH_FDT_NAME 256

typedef struct fwh_prop fwh_prop_t;
typedef struct fwh_node fwh_node_t;

struct fwh_prop {
    const char *name;
    const unsigned char *value;
    size_t len;
    size_t position;
    fwh_prop_t *next;
};

struct fwh_node {
    const char *name;
    fwh_prop_t *props;
    fwh_prop_t *last_prop;
    fwh_node_t *children;
    fwh_node_t *last_child;
    fwh_node_t *next;
    fwh_node_t *parent;
};

typedef struct {
    size_t base;
    size_t struct_abs;
    size_t total;
    const unsigned char *structure;
    size_t struct_len;
    const unsigned char *strings;
    size_t strings_len;
} fwh_fdt_t;

typedef struct {
    fwh_image_t *image;
    fwh_node_t *root;
    fwh_node_t *current;
    int depth;
} fwh_builder_t;

static int fwh_fdt_header(const unsigned char *buf, size_t buf_len, size_t offset, fwh_fdt_t *fdt)
{
    const unsigned char *h = buf + offset;
    uint32_t total, so, sto, ro, version, compat, strings_size, struct_size;
    size_t header;

    if (buf_len - offset < 40 || fwh_u32be(h) != FWH_FDT_MAGIC)
        return FWH_ERR_FORMAT;
    total = fwh_u32be(h + 4);
    so = fwh_u32be(h + 8);
    sto = fwh_u32be(h + 12);
    ro = fwh_u32be(h + 16);
    version = fwh_u32be(h + 20);
    compat = fwh_u32be(h + 24);
    strings_size = fwh_u32be(h + 32);
    if (version < 16 || compat > 17)
        return FWH_ERR_FORMAT;
    header = version >= 17 ? 40 : 36;
    struct_size = version >= 17 ? fwh_u32be(h + 36) : total - so;
    if (total < header || total > buf_len - offset)
        return FWH_ERR_TRUNCATED;
    if (so < header || sto < header || ro < header || so % 4)
        return FWH_ERR_FORMAT;
    if ((uint64_t)so + struct_size > total || (uint64_t)sto + strings_size > total)
        return FWH_ERR_TRUNCATED;
    fdt->base = offset;
    fdt->total = total;
    fdt->struct_abs = offset + so;
    fdt->structure = h + so;
    fdt->struct_len = struct_size;
    fdt->strings = h + sto;
    fdt->strings_len = strings_size;
    return FWH_OK;
}

static size_t fwh_cstring_len(const unsigned char *p, size_t avail)
{
    size_t limit = avail < FWH_FDT_NAME ? avail : FWH_FDT_NAME, i;

    for (i = 0; i < limit; i++)
        if (p[i] == 0)
            return i;
    return (size_t)-1;
}

typedef struct {
    int (*begin)(void *ctx, const unsigned char *name, size_t name_len);
    int (*end)(void *ctx);
    int (*prop)(void *ctx, const unsigned char *name, size_t name_len, const unsigned char *value, size_t len,
                size_t position);
} fwh_fdt_visitor_t;

static int fwh_fdt_prop(const fwh_fdt_t *fdt, size_t *pos, const fwh_fdt_visitor_t *v, void *ctx)
{
    uint32_t len, name_off;
    size_t name_len, at;

    if (fdt->struct_len - *pos < 8)
        return FWH_ERR_TRUNCATED;
    len = fwh_u32be(fdt->structure + *pos);
    name_off = fwh_u32be(fdt->structure + *pos + 4);
    at = *pos + 8;
    if (len > fdt->struct_len - at)
        return FWH_ERR_TRUNCATED;
    *pos = (at + len + 3) & ~(size_t)3;
    if (*pos > fdt->struct_len)
        return FWH_ERR_TRUNCATED;
    if (name_off >= fdt->strings_len)
        return FWH_ERR_FORMAT;
    name_len = fwh_cstring_len(fdt->strings + name_off, fdt->strings_len - name_off);
    if (name_len == (size_t)-1)
        return FWH_ERR_FORMAT;
    return v->prop(ctx, fdt->strings + name_off, name_len, fdt->structure + at, len, fdt->struct_abs + at);
}

static int fwh_fdt_walk(const fwh_fdt_t *fdt, const fwh_fdt_visitor_t *v, void *ctx)
{
    size_t pos = 0, items = 0, name_len;
    int depth = 0, roots = 0, status;
    uint32_t token;

    while (1) {
        if (fdt->struct_len - pos < 4)
            return FWH_ERR_TRUNCATED;
        token = fwh_u32be(fdt->structure + pos);
        pos += 4;
        if (token == FWH_FDT_END)
            break;
        if (++items > FWH_FDT_ITEMS)
            return FWH_ERR_LIMIT;
        if (token == FWH_FDT_BEGIN) {
            name_len = fwh_cstring_len(fdt->structure + pos, fdt->struct_len - pos);
            if (name_len == (size_t)-1)
                return FWH_ERR_FORMAT;
            if (depth >= FWH_FDT_DEPTH)
                return FWH_ERR_LIMIT;
            if (depth == 0 && (roots++ || name_len != 0))
                return FWH_ERR_FORMAT;
            if ((status = v->begin(ctx, fdt->structure + pos, name_len)) != FWH_OK)
                return status;
            pos = (pos + name_len + 1 + 3) & ~(size_t)3;
            if (pos > fdt->struct_len)
                return FWH_ERR_TRUNCATED;
            depth++;
        } else if (token == FWH_FDT_END_NODE) {
            if (depth == 0)
                return FWH_ERR_FORMAT;
            depth--;
            if ((status = v->end(ctx)) != FWH_OK)
                return status;
        } else if (token == FWH_FDT_PROP) {
            if (depth == 0)
                return FWH_ERR_FORMAT;
            if ((status = fwh_fdt_prop(fdt, &pos, v, ctx)) != FWH_OK)
                return status;
        } else if (token != FWH_FDT_NOP) {
            return FWH_ERR_FORMAT;
        }
    }
    return depth == 0 && roots == 1 ? FWH_OK : FWH_ERR_FORMAT;
}

static int fwh_build_begin(void *ctx, const unsigned char *name, size_t name_len)
{
    fwh_builder_t *b = ctx;
    fwh_node_t *node = fwh_scratch(b->image, sizeof(*node));

    if (node == NULL)
        return FWH_ERR_NOMEM;
    memset(node, 0, sizeof(*node));
    (void)name_len;
    node->name = (const char *)name;
    node->parent = b->current;
    if (b->current == NULL) {
        b->root = node;
    } else if (b->current->last_child) {
        b->current->last_child->next = node;
        b->current->last_child = node;
    } else {
        b->current->children = b->current->last_child = node;
    }
    b->current = node;
    return FWH_OK;
}

static int fwh_build_end(void *ctx)
{
    fwh_builder_t *b = ctx;

    b->current = b->current->parent;
    return FWH_OK;
}

static int fwh_build_prop(void *ctx, const unsigned char *name, size_t name_len, const unsigned char *value,
                          size_t len, size_t position)
{
    fwh_builder_t *b = ctx;
    fwh_prop_t *prop = fwh_scratch(b->image, sizeof(*prop));

    (void)name_len;
    if (prop == NULL)
        return FWH_ERR_NOMEM;
    prop->name = (const char *)name;
    prop->value = value;
    prop->len = len;
    prop->position = position;
    prop->next = NULL;
    if (b->current->last_prop)
        b->current->last_prop->next = prop;
    else
        b->current->props = prop;
    b->current->last_prop = prop;
    return FWH_OK;
}

static const fwh_fdt_visitor_t fwh_builder_visitor = {fwh_build_begin, fwh_build_end, fwh_build_prop};

static const fwh_prop_t *fwh_prop(const fwh_node_t *node, const char *name)
{
    const fwh_prop_t *prop, *found = NULL;

    for (prop = node ? node->props : NULL; prop; prop = prop->next)
        if (strcmp(prop->name, name) == 0)
            found = prop;
    return found;
}

static const fwh_node_t *fwh_child(const fwh_node_t *node, const char *name)
{
    const fwh_node_t *child;

    for (child = node ? node->children : NULL; child; child = child->next)
        if (strcmp(child->name, name) == 0)
            return child;
    return NULL;
}

static const char *fwh_prop_text(fwh_image_t *image, const fwh_node_t *node, const char *name)
{
    const fwh_prop_t *prop = fwh_prop(node, name);
    size_t len = 0, limit;

    if (prop == NULL)
        return NULL;
    limit = prop->len < FWH_FDT_NAME ? prop->len : FWH_FDT_NAME;
    while (len < limit && prop->value[len])
        len++;
    return fwh_text(image, prop->value, len);
}

static int fwh_prop_u32(const fwh_node_t *node, const char *name, uint32_t *out)
{
    const fwh_prop_t *prop = fwh_prop(node, name);

    if (prop == NULL)
        return 0;
    if (prop->len != 4)
        return -1;
    *out = fwh_u32be(prop->value);
    return 1;
}

static int fwh_starts(const char *text, const char *prefix)
{
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static int fwh_fdt_tree(fwh_image_t *image, size_t offset, fwh_fdt_t *fdt, fwh_node_t **out_root)
{
    fwh_builder_t b;
    int status = fwh_fdt_header(image->buf, image->buf_len, offset, fdt);

    if (status != FWH_OK)
        return fwh_fail(image, status, offset);
    memset(&b, 0, sizeof(b));
    b.image = image;
    status = fwh_fdt_walk(fdt, &fwh_builder_visitor, &b);
    if (status != FWH_OK)
        return fwh_fail(image, status, offset);
    *out_root = b.root;
    return FWH_OK;
}

typedef struct {
    int depth;
    int in_images;
    int image_payloads;
    int fit_broken;
    int has_data;
    int has_size;
    int has_place;
    uint32_t size;
    uint32_t place;
    int place_is_position;
    size_t total;
    size_t base;
    size_t buf_len;
} fwh_fit_probe_t;

static int fwh_fp_begin(void *ctx, const unsigned char *name, size_t name_len)
{
    fwh_fit_probe_t *p = ctx;

    p->depth++;
    if (p->depth == 2)
        p->in_images = name_len == 6 && memcmp(name, "images", 6) == 0;
    if (p->depth == 3) {
        p->has_data = p->has_size = p->has_place = 0;
        p->place_is_position = 0;
    }
    return FWH_OK;
}

static uint64_t fwh_external_position(uint64_t total, uint32_t place, int is_position)
{
    return is_position ? place : ((total + 3) & ~(uint64_t)3) + place;
}

static int fwh_fp_end(void *ctx)
{
    fwh_fit_probe_t *p = ctx;
    uint64_t position;

    if (p->depth == 3 && p->in_images) {
        if (p->has_data) {
            p->image_payloads++;
        } else if (p->has_size && p->has_place) {
            position = fwh_external_position(p->total, p->place, p->place_is_position);
            if (position + p->size > p->buf_len - p->base)
                p->fit_broken = 1;
            else
                p->image_payloads++;
        }
    }
    p->depth--;
    return FWH_OK;
}

static int fwh_fp_u32(fwh_fit_probe_t *p, const unsigned char *value, size_t len, uint32_t *out)
{
    if (len != 4) {
        p->fit_broken = 1;
        return 0;
    }
    *out = fwh_u32be(value);
    return 1;
}

static int fwh_fp_prop(void *ctx, const unsigned char *name, size_t name_len, const unsigned char *value,
                       size_t len, size_t position)
{
    fwh_fit_probe_t *p = ctx;

    (void)position;
    if (p->depth != 3 || !p->in_images)
        return FWH_OK;
    if (name_len == 4 && memcmp(name, "data", 4) == 0)
        p->has_data = 1;
    else if (name_len == 9 && memcmp(name, "data-size", 9) == 0)
        p->has_size = fwh_fp_u32(p, value, len, &p->size);
    else if (name_len == 13 && memcmp(name, "data-position", 13) == 0)
        p->has_place = p->place_is_position = fwh_fp_u32(p, value, len, &p->place);
    else if (name_len == 11 && memcmp(name, "data-offset", 11) == 0 && !p->place_is_position)
        p->has_place = fwh_fp_u32(p, value, len, &p->place);
    return FWH_OK;
}

static const fwh_fdt_visitor_t fwh_fit_probe_visitor = {fwh_fp_begin, fwh_fp_end, fwh_fp_prop};

FWH_INTERNAL int fwh_probe_fdt(const unsigned char *buf, size_t buf_len, size_t offset)
{
    fwh_fdt_t fdt;
    fwh_fit_probe_t p;

    if (fwh_fdt_header(buf, buf_len, offset, &fdt) != FWH_OK)
        return FWH_FMT_NONE;
    memset(&p, 0, sizeof(p));
    p.total = fdt.total;
    p.base = offset;
    p.buf_len = buf_len;
    if (fwh_fdt_walk(&fdt, &fwh_fit_probe_visitor, &p) != FWH_OK)
        return FWH_FMT_NONE;
    return p.image_payloads > 0 && !p.fit_broken ? FWH_FMT_FIT : FWH_FMT_DTB;
}

static const char *const fwh_loadables[] = {"kernel", "fdt", "ramdisk", "loadables", "firmware", "setup", "script"};

static int fwh_fit_role(const char *type)
{
    static const char *const names[] = {"kernel", "kernel_noload", "ramdisk", "flat_dt", "firmware", "script",
                                        "filesystem", "standalone"};
    static const int roles[] = {FWH_ROLE_KERNEL,   FWH_ROLE_KERNEL, FWH_ROLE_RAMDISK, FWH_ROLE_FDT,
                                FWH_ROLE_FIRMWARE, FWH_ROLE_SCRIPT, FWH_ROLE_ROOTFS,  FWH_ROLE_FIRMWARE};
    size_t i;

    for (i = 0; type && i < sizeof(names) / sizeof(names[0]); i++)
        if (strcmp(type, names[i]) == 0)
            return roles[i];
    return FWH_ROLE_OTHER;
}

static int fwh_fit_payload(fwh_image_t *image, const fwh_node_t *node, size_t offset, size_t total, size_t *out_at,
                           size_t *out_len, uint64_t *out_end)
{
    const fwh_prop_t *data = fwh_prop(node, "data");
    uint32_t size, position, relative;
    int has_size, has_position, has_relative;
    uint64_t place;

    *out_end = total;
    if (data) {
        *out_at = data->position;
        *out_len = data->len;
        return 1;
    }
    has_size = fwh_prop_u32(node, "data-size", &size);
    has_position = fwh_prop_u32(node, "data-position", &position);
    has_relative = fwh_prop_u32(node, "data-offset", &relative);
    if (has_size < 0 || has_position < 0 || has_relative < 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset) * -1;
    if (!has_size || (!has_position && !has_relative))
        return 0;
    place = fwh_external_position(total, has_position ? position : relative, has_position);
    if (!fwh_has(image, offset + place, size))
        return fwh_fail(image, FWH_ERR_TRUNCATED, offset) * -1;
    *out_at = offset + (size_t)place;
    *out_len = size;
    *out_end = place + size > total ? place + size : total;
    return 1;
}

static const char *fwh_fit_detail(fwh_image_t *image, const fwh_node_t *node)
{
    const char *keys[] = {"type", "arch", "compression"};
    const char *parts[3];
    size_t i, n = 0;

    for (i = 0; i < 3; i++) {
        const char *value = fwh_prop_text(image, node, keys[i]);

        if (value && *value)
            parts[n++] = value;
    }
    if (n == 0)
        return "";
    if (n == 1)
        return parts[0];
    if (n == 2)
        return fwh_printf(image, "%s, %s", parts[0], parts[1]);
    return fwh_printf(image, "%s, %s, %s", parts[0], parts[1], parts[2]);
}

static int fwh_fit_hash(fwh_image_t *image, const fwh_node_t *image_node, const fwh_node_t *hash, size_t at,
                        size_t len)
{
    const char *algo = fwh_prop_text(image, hash, "algo");
    const fwh_prop_t *value = fwh_prop(hash, "value");
    fwh_checksum_t *check;
    size_t digest_len = 0;

    if (algo == NULL || value == NULL)
        return FWH_OK;
    check = fwh_add_check(image, algo, FWH_SCOPE_IMAGE, image_node->name, at, len);
    if (check == NULL)
        return FWH_ERR_NOMEM;
    check->digest_len = value->len < FWH_DIGEST_MAX ? value->len : FWH_DIGEST_MAX;
    memcpy(check->expected, value->value, check->digest_len);
    if (fwh_digest2(algo, image->buf + at, len, NULL, 0, check->computed, &digest_len) != FWH_OK)
        return FWH_OK;
    check->state = digest_len == value->len && memcmp(check->computed, value->value, digest_len) == 0
                       ? FWH_CHECK_OK
                       : FWH_CHECK_BAD;
    return FWH_OK;
}

static int fwh_fit_signature(fwh_image_t *image, const char *owner, const fwh_node_t *sig_node, int scope,
                             const char *covers)
{
    const char *algo = fwh_prop_text(image, sig_node, "algo");
    fwh_signature_t *sig;

    if (algo == NULL || *algo == '\0')
        return FWH_OK;
    sig = fwh_add_sig(image, fwh_printf(image, "%s/%s", owner, sig_node->name), algo, scope, covers);
    if (sig == NULL)
        return FWH_ERR_NOMEM;
    sig->key_hint = fwh_prop_text(image, sig_node, "key-name-hint");
    if (sig->key_hint == NULL)
        sig->key_hint = "";
    return FWH_OK;
}

static int fwh_fit_image(fwh_image_t *image, const fwh_node_t *node, size_t offset, size_t total, uint64_t *end)
{
    const fwh_node_t *child;
    size_t at = 0, len = 0;
    uint64_t node_end;
    int found = fwh_fit_payload(image, node, offset, total, &at, &len, &node_end), status;
    fwh_part_t *part;

    if (found < 0)
        return -found;
    if (found == 0)
        return FWH_OK;
    if (node_end > *end)
        *end = node_end;
    part = fwh_add_part(image, node->name, at, len, fwh_fit_role(fwh_prop_text(image, node, "type")));
    if (part == NULL)
        return FWH_ERR_NOMEM;
    part->detail = fwh_fit_detail(image, node);
    part->compression = fwh_prop_text(image, node, "compression");
    if (part->compression == NULL)
        part->compression = "";
    for (child = node->children; child; child = child->next) {
        if (fwh_starts(child->name, "hash"))
            status = fwh_fit_hash(image, node, child, at, len);
        else if (fwh_starts(child->name, "signature"))
            status = fwh_fit_signature(image, node->name, child, FWH_SCOPE_IMAGE, node->name);
        else
            continue;
        if (status != FWH_OK)
            return status;
    }
    return FWH_OK;
}

static const char *fwh_prop_list(fwh_image_t *image, const fwh_node_t *node, const char *name)
{
    const fwh_prop_t *prop = fwh_prop(node, name);
    char *text, *out;
    size_t i = 0, len, start;

    if (prop == NULL)
        return NULL;
    len = prop->len < FWH_FDT_NAME * 8 ? prop->len : FWH_FDT_NAME * 8;
    if ((text = fwh_scratch(image, len * 2 + 1)) == NULL)
        return NULL;
    out = text;
    while (i < len) {
        for (start = i; i < len && prop->value[i]; i++)
            ;
        if (i > start) {
            if (out != text) {
                memcpy(out, ", ", 2);
                out += 2;
            }
            memcpy(out, prop->value + start, i - start);
            out += i - start;
        }
        i++;
    }
    *out = '\0';
    return text;
}

static const char *fwh_config_loads(fwh_image_t *image, const fwh_node_t *node)
{
    char *text = fwh_scratch(image, 128), *out = text;
    size_t i, len;

    if (text == NULL)
        return NULL;
    *out = '\0';
    for (i = 0; i < sizeof(fwh_loadables) / sizeof(fwh_loadables[0]); i++) {
        if (fwh_prop(node, fwh_loadables[i]) == NULL)
            continue;
        if (out != text) {
            memcpy(out, ", ", 2);
            out += 2;
        }
        len = strlen(fwh_loadables[i]);
        memcpy(out, fwh_loadables[i], len + 1);
        out += len;
    }
    return text;
}

static int fwh_fit_config(fwh_image_t *image, const fwh_node_t *node)
{
    const fwh_node_t *child;
    const char *covers;
    int status;

    if (fwh_add_config(image, node->name, fwh_config_loads(image, node)) == NULL)
        return FWH_ERR_NOMEM;
    for (child = node->children; child; child = child->next) {
        if (!fwh_starts(child->name, "signature"))
            continue;
        covers = fwh_prop_list(image, child, "sign-images");
        if (covers == NULL || *covers == '\0')
            covers = "(default)";
        if ((status = fwh_fit_signature(image, node->name, child, FWH_SCOPE_CONFIGURATION, covers)) != FWH_OK)
            return status;
    }
    return FWH_OK;
}

static int fwh_fdt_keys(fwh_image_t *image, const fwh_node_t *root)
{
    const fwh_node_t *holder = fwh_child(root, "signature"), *node;
    fwh_key_t *key;
    uint32_t bits;

    for (node = holder ? holder->children : NULL; node; node = node->next) {
        if ((key = fwh_add_key(image, fwh_printf(image, "signature/%s", node->name))) == NULL)
            return FWH_ERR_NOMEM;
        key->algorithm = fwh_prop_text(image, node, "algo");
        key->required = fwh_prop_text(image, node, "required");
        key->key_hint = fwh_prop_text(image, node, "key-name-hint");
        if (key->algorithm == NULL)
            key->algorithm = "";
        if (key->required == NULL)
            key->required = "";
        if (key->key_hint == NULL || *key->key_hint == '\0')
            key->key_hint = node->name;
        if (fwh_prop_u32(node, "rsa,num-bits", &bits) == 1)
            key->bits = bits;
    }
    return FWH_OK;
}

static int fwh_fit_integrity(fwh_image_t *image)
{
    const fwh_checksum_t *checks = image->checks.items;
    const char *seen[16];
    size_t i, j, n = 0;
    char text[256] = "";

    for (i = 0; i < image->checks.count && n < 16; i++) {
        for (j = 0; j < n && strcmp(seen[j], checks[i].algorithm) != 0; j++)
            ;
        if (j == n)
            seen[n++] = checks[i].algorithm;
    }
    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++)
            if (strcmp(seen[j], seen[i]) < 0) {
                const char *t = seen[i];
                seen[i] = seen[j];
                seen[j] = t;
            }
    for (i = 0; i < n; i++) {
        if (i)
            strncat(text, ", ", sizeof(text) - strlen(text) - 1);
        strncat(text, seen[i], sizeof(text) - strlen(text) - 1);
    }
    return n ? fwh_add_meta(image, "integrity", fwh_text(image, text, strlen(text))) : FWH_OK;
}

static int fwh_fit_description(fwh_image_t *image, const fwh_node_t *root)
{
    const fwh_part_t *parts = image->parts.items;
    const fwh_node_t *images = fwh_child(root, "images");
    const char *text = "", *type;
    size_t i;

    for (i = 0; i < image->parts.count; i++) {
        const fwh_node_t *node = fwh_child(images, parts[i].name);

        type = fwh_prop_text(image, node, "type");
        if (type && *type)
            text = fwh_printf(image, "%s%s%s (%s)", text, i ? ", " : "", parts[i].name, type);
        else
            text = fwh_printf(image, "%s%s%s", text, i ? ", " : "", parts[i].name);
        if (text == NULL)
            return FWH_ERR_NOMEM;
        if (strlen(text) > 1024) {
            text = fwh_printf(image, "%s, ...", text);
            break;
        }
    }
    image->description = text;
    return FWH_OK;
}

FWH_INTERNAL int fwh_parse_fit(fwh_image_t *image, size_t offset)
{
    fwh_fdt_t fdt;
    fwh_node_t *root;
    const fwh_node_t *node;
    uint64_t end;
    int status = fwh_fdt_tree(image, offset, &fdt, &root);

    if (status != FWH_OK)
        return status;
    end = fdt.total;
    for (node = fwh_child(root, "images") ? fwh_child(root, "images")->children : NULL; node; node = node->next)
        if ((status = fwh_fit_image(image, node, offset, fdt.total, &end)) != FWH_OK)
            return status;
    if (image->parts.count == 0)
        return fwh_fail(image, FWH_ERR_FORMAT, offset);
    for (node = fwh_child(root, "configurations") ? fwh_child(root, "configurations")->children : NULL; node;
         node = node->next)
        if ((status = fwh_fit_config(image, node)) != FWH_OK)
            return status;
    if ((status = fwh_fdt_keys(image, root)) != FWH_OK || (status = fwh_fit_integrity(image)) != FWH_OK)
        return status;
    image->size = end;
    image->scratch = root;
    return fwh_fit_description(image, root);
}

FWH_INTERNAL int fwh_parse_dtb(fwh_image_t *image, size_t offset)
{
    fwh_fdt_t fdt;
    fwh_node_t *root;
    const char *board;
    int status = fwh_fdt_tree(image, offset, &fdt, &root);

    if (status != FWH_OK)
        return status;
    board = fwh_prop_text(image, root, "model");
    if (board == NULL || *board == '\0')
        board = fwh_prop_text(image, root, "compatible");
    if (board == NULL || *board == '\0')
        board = "no model";
    image->size = fdt.total;
    image->scratch = root;
    image->description = fwh_printf(image, "device tree, %s", board);
    if (image->description == NULL || fwh_add_meta(image, "board", board))
        return FWH_ERR_NOMEM;
    return fwh_fdt_keys(image, root);
}
