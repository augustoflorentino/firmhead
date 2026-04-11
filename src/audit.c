#include "firmhead/firmhead.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define FWH_MIN_RSA 2048u

static int fwh_contains(const char *text, const char *word)
{
    return text != NULL && strstr(text, word) != NULL;
}

static unsigned fwh_rsa_bits(const char *algorithm)
{
    const char *p = strstr(algorithm, "rsa");

    if (p == NULL || p[3] < '0' || p[3] > '9')
        return 0;
    return (unsigned)strtoul(p + 3, NULL, 10);
}

static int fwh_weak(const char *algorithm, unsigned bits)
{
    char lower[64];
    size_t i;
    unsigned named;

    for (i = 0; algorithm[i] && i < sizeof(lower) - 1; i++)
        lower[i] = (char)(algorithm[i] >= 'A' && algorithm[i] <= 'Z' ? algorithm[i] + 32 : algorithm[i]);
    lower[i] = '\0';
    named = fwh_rsa_bits(lower);
    return fwh_contains(lower, "sha1") || fwh_contains(lower, "md5") || (bits && bits < FWH_MIN_RSA) ||
           (named && named < FWH_MIN_RSA);
}

static const char *fwh_append(fwh_image_t *image, const char *text, const char *item)
{
    if (text == NULL || *text == '\0')
        return item;
    if (strlen(text) > 2048)
        return text;
    return fwh_printf(image, "%s; %s", text, item);
}

static const char *fwh_describe(fwh_image_t *image, const char *node, const char *algorithm, unsigned bits)
{
    if (bits)
        return fwh_printf(image, "%s: %s, %u-bit key", node, *algorithm ? algorithm : "rsa", bits);
    return fwh_printf(image, "%s: %s", node, *algorithm ? algorithm : "rsa");
}

static int fwh_audit_weak(fwh_image_t *image)
{
    const fwh_signature_t *sigs = image->sigs.items;
    const fwh_key_t *keys = image->keys.items;
    const char *evidence = "";
    size_t i, weak = 0;

    for (i = 0; i < image->sigs.count; i++)
        if (fwh_weak(sigs[i].algorithm, sigs[i].bits) && ++weak)
            evidence = fwh_append(image, evidence, fwh_describe(image, sigs[i].node, sigs[i].algorithm, sigs[i].bits));
    for (i = 0; i < image->keys.count; i++)
        if (fwh_weak(keys[i].algorithm, keys[i].bits) && ++weak)
            evidence = fwh_append(image, evidence, fwh_describe(image, keys[i].node, keys[i].algorithm, keys[i].bits));
    if (weak == 0)
        return FWH_OK;
    return fwh_add_finding(image, FWH_FIND_WEAK, fwh_format_name(image->format), evidence) ? FWH_OK : FWH_ERR_NOMEM;
}

static int fwh_audit_images_only(fwh_image_t *image)
{
    const fwh_signature_t *sigs = image->sigs.items;
    const char *signed_nodes = "";
    size_t i;

    if (image->sigs.count == 0)
        return FWH_OK;
    for (i = 0; i < image->sigs.count; i++) {
        if (sigs[i].scope != FWH_SCOPE_IMAGE)
            return FWH_OK;
        signed_nodes = *signed_nodes ? fwh_printf(image, "%s, %s", signed_nodes, sigs[i].node) : sigs[i].node;
    }
    return fwh_add_finding(image, FWH_FIND_IMAGES_ONLY, "images", fwh_printf(image, "signed: %s", signed_nodes))
               ? FWH_OK
               : FWH_ERR_NOMEM;
}

static int fwh_listed(const char *list, const char *name, size_t name_len)
{
    const char *p = list;

    while (p && *p) {
        const char *end = strstr(p, ", ");
        size_t len = end ? (size_t)(end - p) : strlen(p);

        if (len == name_len && strncmp(p, name, len) == 0)
            return 1;
        p = end ? end + 2 : NULL;
    }
    return 0;
}

static const char *fwh_missing(fwh_image_t *image, const char *loads, const char *covers)
{
    const char *p = loads, *missing = "";

    while (p && *p) {
        const char *end = strstr(p, ", ");
        size_t len = end ? (size_t)(end - p) : strlen(p);

        if (!fwh_listed(covers, p, len))
            missing = *missing ? fwh_printf(image, "%s, %.*s", missing, (int)len, p)
                               : fwh_printf(image, "%.*s", (int)len, p);
        p = end ? end + 2 : NULL;
    }
    return missing;
}

static const fwh_config_t *fwh_find_config(const fwh_image_t *image, const char *node)
{
    const fwh_config_t *configs = image->configs.items;
    const char *slash = strchr(node, '/');
    size_t len = slash ? (size_t)(slash - node) : strlen(node), i;

    for (i = 0; i < image->configs.count; i++)
        if (strlen(configs[i].name) == len && strncmp(configs[i].name, node, len) == 0)
            return &configs[i];
    return NULL;
}

static int fwh_audit_partial(fwh_image_t *image)
{
    const fwh_signature_t *sigs = image->sigs.items;
    const fwh_config_t *config;
    const char *missing;
    size_t i;

    for (i = 0; i < image->sigs.count; i++) {
        if (sigs[i].scope != FWH_SCOPE_CONFIGURATION || fwh_listed(sigs[i].covers, "(default)", 9))
            continue;
        if ((config = fwh_find_config(image, sigs[i].node)) == NULL)
            continue;
        missing = fwh_missing(image, config->loads, sigs[i].covers);
        if (missing == NULL)
            return FWH_ERR_NOMEM;
        if (*missing == '\0')
            continue;
        if (!fwh_add_finding(image, FWH_FIND_PARTIAL_CONFIG, config->name,
                             fwh_printf(image, "%s: sign-images = %s; also loads %s", sigs[i].node, sigs[i].covers,
                                        missing)))
            return FWH_ERR_NOMEM;
    }
    return FWH_OK;
}

static int fwh_audit_keys(fwh_image_t *image)
{
    const fwh_key_t *keys = image->keys.items;
    const char *names = "";
    size_t i;

    if (image->keys.count == 0)
        return FWH_OK;
    for (i = 0; i < image->keys.count; i++) {
        if (*keys[i].required)
            return FWH_OK;
        names = fwh_append(image, names,
                           fwh_printf(image, "%s (%s)", keys[i].key_hint, *keys[i].algorithm ? keys[i].algorithm : "rsa"));
    }
    return fwh_add_finding(image, FWH_FIND_OPTIONAL_KEYS, "signature",
                           fwh_printf(image, "keys without 'required': %s", names))
               ? FWH_OK
               : FWH_ERR_NOMEM;
}

static int fwh_ambiguous_list(fwh_image_t *image, const char *where, const char *const *names, size_t count)
{
    size_t i, j;

    for (i = 0; i < count; i++) {
        int duplicate = 0;

        for (j = 0; j < i && !duplicate; j++)
            duplicate = strcmp(names[i], names[j]) == 0;
        if (!strchr(names[i], '@') && !duplicate)
            continue;
        if (!fwh_add_finding(image, FWH_FIND_AMBIGUOUS_NODE, where,
                             fwh_printf(image, "%s/%s: %s", where, names[i],
                                        duplicate ? "duplicate node name" : "unit address in node name")))
            return FWH_ERR_NOMEM;
    }
    return FWH_OK;
}

static int fwh_audit_ambiguous(fwh_image_t *image)
{
    const fwh_part_t *parts = image->parts.items;
    const fwh_config_t *configs = image->configs.items;
    const char **names;
    size_t i, count = image->parts.count > image->configs.count ? image->parts.count : image->configs.count;
    int status;

    if (image->format != FWH_FMT_FIT || count == 0)
        return FWH_OK;
    if ((names = fwh_scratch(image, count * sizeof(*names))) == NULL)
        return FWH_ERR_NOMEM;
    for (i = 0; i < image->parts.count; i++)
        names[i] = parts[i].name;
    if ((status = fwh_ambiguous_list(image, "images", names, image->parts.count)) != FWH_OK)
        return status;
    for (i = 0; i < image->configs.count; i++)
        names[i] = configs[i].name;
    return fwh_ambiguous_list(image, "configurations", names, image->configs.count);
}

int fwh_audit(fwh_image_t *image)
{
    int status;

    if (image == NULL)
        return FWH_ERR_ARG;
    if (image->audited)
        return FWH_OK;
    if ((status = fwh_audit_weak(image)) != FWH_OK || (status = fwh_audit_images_only(image)) != FWH_OK ||
        (status = fwh_audit_partial(image)) != FWH_OK || (status = fwh_audit_keys(image)) != FWH_OK ||
        (status = fwh_audit_ambiguous(image)) != FWH_OK)
        return status;
    image->audited = 1;
    return FWH_OK;
}
