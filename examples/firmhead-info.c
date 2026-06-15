#include <firmhead/firmhead.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    long len;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (len = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0 &&
        (buf = malloc((size_t)len + 1)) != NULL && fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        buf = NULL;
    }
    if (buf)
        *out_len = (size_t)len;
    fclose(f);
    return buf;
}

static void print_hex(const unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static void print_checks(const fwh_image_t *image)
{
    size_t i;

    for (i = 0; i < fwh_checksum_count(image); i++) {
        const fwh_checksum_t *c = fwh_checksum_get(image, i);

        printf("  check %-10s %-13s %-12s %s  ", c->algorithm, fwh_scope_name(c->scope), fwh_check_name(c->state),
               c->covers);
        print_hex(c->expected, c->digest_len);
        printf("\n");
    }
}

static void print_image(const fwh_image_t *image)
{
    size_t i;

    printf("%s@0x%llx size %llu: %s\n", fwh_format_name(fwh_image_format(image)),
           (unsigned long long)fwh_image_offset(image), (unsigned long long)fwh_image_size(image),
           fwh_image_description(image));
    for (i = 0; i < fwh_part_count(image); i++) {
        const fwh_part_t *p = fwh_part_get(image, i);

        printf("  part  %-20s 0x%08llx %10llu %-9s %s\n", p->name, (unsigned long long)p->offset,
               (unsigned long long)p->size, fwh_role_name(p->role), p->compression);
    }
    for (i = 0; i < fwh_meta_count(image); i++)
        printf("  meta  %s = %s\n", fwh_meta_get(image, i)->key, fwh_meta_get(image, i)->value);
    print_checks(image);
    for (i = 0; i < fwh_signature_count(image); i++) {
        const fwh_signature_t *s = fwh_signature_get(image, i);

        printf("  sig   %s %s %s covers %s\n", s->node, s->algorithm, fwh_scope_name(s->scope), s->covers);
        if (s->value_size)
            printf("        value 0x%llx+%llu", (unsigned long long)s->value_offset, (unsigned long long)s->value_size);
        if (s->signed_size)
            printf(", signs 0x%llx+%llu", (unsigned long long)s->signed_offset, (unsigned long long)s->signed_size);
        if (s->value_size)
            printf("%s%s\n", *s->key_hint ? ", " : "", s->key_hint);
    }
    for (i = 0; i < fwh_key_count(image); i++) {
        const fwh_key_t *k = fwh_key_get(image, i);

        printf("  key   %s %s %u required=%s\n", k->key_hint, k->algorithm, k->bits, k->required);
    }
    for (i = 0; i < fwh_finding_count(image); i++) {
        const fwh_finding_t *f = fwh_finding_get(image, i);

        printf("  find  %s %s: %s\n", fwh_finding_name(f->code), f->where, f->evidence);
    }
}

static void json_string(const char *text)
{
    const unsigned char *c;

    putchar('"');
    for (c = (const unsigned char *)text; *c; c++) {
        if (*c == '"' || *c == '\\')
            printf("\\%c", *c);
        else if (*c < 0x20 || *c >= 0x7f)
            printf("\\u%04x", *c);
        else
            putchar(*c);
    }
    putchar('"');
}

static void json_key(const char *key, const char *value, int last)
{
    printf("\"%s\":", key);
    json_string(value);
    printf(last ? "" : ",");
}

static void json_parts(const fwh_image_t *image)
{
    size_t i;

    printf("\"parts\":[");
    for (i = 0; i < fwh_part_count(image); i++) {
        const fwh_part_t *p = fwh_part_get(image, i);

        printf("%s{", i ? "," : "");
        json_key("name", p->name, 0);
        json_key("role", fwh_role_name(p->role), 0);
        json_key("compression", p->compression, 0);
        printf("\"offset\":%llu,\"size\":%llu}", (unsigned long long)p->offset, (unsigned long long)p->size);
    }
    printf("],\"meta\":[");
    for (i = 0; i < fwh_meta_count(image); i++) {
        printf("%s[", i ? "," : "");
        json_string(fwh_meta_get(image, i)->key);
        putchar(',');
        json_string(fwh_meta_get(image, i)->value);
        putchar(']');
    }
    printf("]");
}

static void json_checks(const fwh_image_t *image)
{
    size_t i;

    printf(",\"checks\":[");
    for (i = 0; i < fwh_checksum_count(image); i++) {
        const fwh_checksum_t *c = fwh_checksum_get(image, i);

        printf("%s{", i ? "," : "");
        json_key("algorithm", c->algorithm, 0);
        json_key("scope", fwh_scope_name(c->scope), 0);
        json_key("covers", c->covers, 0);
        json_key("state", fwh_check_name(c->state), 0);
        printf("\"offset\":%llu,\"size\":%llu,\"expected\":\"", (unsigned long long)c->offset,
               (unsigned long long)c->size);
        print_hex(c->expected, c->digest_len);
        printf("\"}");
    }
    printf("]");
}

static void json_signing(const fwh_image_t *image)
{
    size_t i;

    printf(",\"signatures\":[");
    for (i = 0; i < fwh_signature_count(image); i++) {
        const fwh_signature_t *s = fwh_signature_get(image, i);

        printf("%s{", i ? "," : "");
        json_key("node", s->node, 0);
        json_key("algorithm", s->algorithm, 0);
        json_key("key", s->key_hint, 0);
        json_key("scope", fwh_scope_name(s->scope), 0);
        printf("\"value_offset\":%llu,\"value_size\":%llu,\"signed_offset\":%llu,\"signed_size\":%llu}",
               (unsigned long long)s->value_offset, (unsigned long long)s->value_size,
               (unsigned long long)s->signed_offset, (unsigned long long)s->signed_size);
    }
    printf("],\"findings\":[");
    for (i = 0; i < fwh_finding_count(image); i++) {
        const fwh_finding_t *f = fwh_finding_get(image, i);

        printf("%s{", i ? "," : "");
        json_key("code", fwh_finding_name(f->code), 0);
        json_key("where", f->where, 0);
        json_key("evidence", f->evidence, 1);
        printf("}");
    }
    printf("]");
}

static void json_image(const fwh_image_t *image, int first)
{
    printf("%s{", first ? "" : ",");
    json_key("format", fwh_format_name(fwh_image_format(image)), 0);
    json_key("description", fwh_image_description(image), 0);
    printf("\"offset\":%llu,\"size\":%llu,", (unsigned long long)fwh_image_offset(image),
           (unsigned long long)fwh_image_size(image));
    json_parts(image);
    json_checks(image);
    json_signing(image);
    printf("}");
}

static int damaged(const fwh_image_t *image)
{
    size_t i;

    for (i = 0; i < fwh_checksum_count(image); i++)
        if (fwh_checksum_get(image, i)->state == FWH_CHECK_BAD)
            return 1;
    return 0;
}

static int scan(const unsigned char *buf, size_t len, int json)
{
    int bad = 0;
    size_t found = 0;
    size_t offset, error_at;
    uint64_t formats;
    fwh_image_t *image;
    int status;

    for (offset = 0; offset < len; offset++) {
        if (fwh_probe(buf, len, offset, &formats) != FWH_OK || formats == 0)
            continue;
        status = fwh_open(buf, len, offset, FWH_FMT_NONE, FWH_OPEN_AUDIT, NULL, &image, &error_at);
        if (status != FWH_OK) {
            if (!json)
                printf("0x%zx: %s at 0x%zx\n", offset, fwh_strerror(status), error_at);
            continue;
        }
        if (json)
            json_image(image, found++ == 0);
        else
            print_image(image);
        bad |= damaged(image);
        fwh_image_destroy(image);
    }
    return bad;
}

int main(int argc, char **argv)
{
    unsigned char *buf;
    size_t len = 0;
    int i, bad = 0, json = argc > 1 && strcmp(argv[1], "-j") == 0;

    if (argc == 2 && strcmp(argv[1], "-V") == 0) {
        printf("firmhead %s\n", fwh_version());
        return 0;
    }
    if (argc < 2 + json) {
        fprintf(stderr, "usage: %s [-V] [-j] firmware...\n", argv[0]);
        return 2;
    }
    for (i = 1 + json; i < argc; i++) {
        if ((buf = read_file(argv[i], &len)) == NULL) {
            perror(argv[i]);
            return 1;
        }
        if (json) {
            printf("{\"file\":");
            json_string(argv[i]);
            printf(",\"images\":[");
        } else {
            printf("== %s\n", argv[i]);
        }
        bad |= scan(buf, len, json);
        printf(json ? "]}\n" : "");
        free(buf);
    }
    return bad ? 3 : 0;
}
