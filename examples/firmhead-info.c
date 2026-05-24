#include <firmhead/firmhead.h>

#include <stdio.h>
#include <stdlib.h>

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

static void scan(const unsigned char *buf, size_t len)
{
    size_t offset, error_at;
    unsigned formats;
    fwh_image_t *image;
    int status;

    for (offset = 0; offset < len; offset++) {
        if (fwh_probe(buf, len, offset, &formats) != FWH_OK || formats == 0)
            continue;
        status = fwh_open(buf, len, offset, FWH_FMT_NONE, NULL, &image, &error_at);
        if (status != FWH_OK) {
            printf("0x%zx: %s at 0x%zx\n", offset, fwh_strerror(status), error_at);
            continue;
        }
        if (fwh_audit(image) == FWH_OK)
            print_image(image);
        fwh_image_destroy(image);
    }
}

int main(int argc, char **argv)
{
    unsigned char *buf;
    size_t len = 0;
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: %s firmware...\n", argv[0]);
        return 2;
    }
    for (i = 1; i < argc; i++) {
        if ((buf = read_file(argv[i], &len)) == NULL) {
            perror(argv[i]);
            return 1;
        }
        printf("== %s\n", argv[i]);
        scan(buf, len);
        free(buf);
    }
    return 0;
}
