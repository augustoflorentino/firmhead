#ifndef FIRMHEAD_INTERNAL_H
#define FIRMHEAD_INTERNAL_H

#include "firmhead/firmhead.h"

#ifdef FWH_STATIC
#define FWH_INTERNAL static
#else
#define FWH_INTERNAL
#endif

#define FWH_LIST_LIMIT 65536
#define FWH_TEXT_LIMIT 4096

typedef struct fwh_chunk fwh_chunk_t;

typedef struct {
    void *items;
    size_t count;
    size_t cap;
} fwh_list_t;

struct fwh_image {
    fwh_alloc_fn alloc_fn;
    fwh_free_fn free_fn;
    void *alloc_ctx;
    const unsigned char *buf;
    size_t buf_len;
    int format;
    uint64_t offset;
    uint64_t size;
    const char *description;
    int audited;
    size_t error_at;
    fwh_list_t parts;
    fwh_list_t metas;
    fwh_list_t checks;
    fwh_list_t sigs;
    fwh_list_t keys;
    fwh_list_t configs;
    fwh_list_t findings;
    fwh_chunk_t *chunks;
    void *scratch;
};

typedef int (*fwh_parse_fn)(fwh_image_t *image, size_t offset);

FWH_INTERNAL int fwh_digest2(const char *algorithm, const unsigned char *a, size_t a_len, const unsigned char *b,
                             size_t b_len, unsigned char *out_digest, size_t *out_digest_len);

FWH_INTERNAL int fwh_digest_parts(const char *algorithm, const unsigned char *const *data, const size_t *lens, size_t n,
                                  unsigned char *out_digest);
FWH_INTERNAL int fwh_fail(fwh_image_t *image, int status, size_t at);
FWH_INTERNAL int fwh_has(const fwh_image_t *image, uint64_t offset, uint64_t size);
FWH_INTERNAL uint32_t fwh_u32be(const unsigned char *p);
FWH_INTERNAL uint32_t fwh_u32le(const unsigned char *p);
FWH_INTERNAL uint16_t fwh_u16le(const unsigned char *p);

FWH_INTERNAL const char *fwh_text(fwh_image_t *image, const void *data, size_t len);
FWH_INTERNAL const char *fwh_ctext(fwh_image_t *image, const unsigned char *data, size_t limit);
FWH_INTERNAL const char *fwh_printf(fwh_image_t *image, const char *fmt, ...);
FWH_INTERNAL const char *fwh_join_parts(fwh_image_t *image, size_t first, int skip_role);
FWH_INTERNAL void *fwh_scratch(fwh_image_t *image, size_t size);

FWH_INTERNAL fwh_part_t *fwh_add_part(fwh_image_t *image, const char *name, uint64_t offset, uint64_t size, int role);
FWH_INTERNAL int fwh_add_meta(fwh_image_t *image, const char *key, const char *value);
FWH_INTERNAL fwh_checksum_t *fwh_add_check(fwh_image_t *image, const char *algorithm, int scope, const char *covers,
                                           uint64_t offset, uint64_t size);
FWH_INTERNAL fwh_signature_t *fwh_add_sig(fwh_image_t *image, const char *node, const char *algorithm, int scope,
                                          const char *covers);
FWH_INTERNAL fwh_key_t *fwh_add_key(fwh_image_t *image, const char *node);
FWH_INTERNAL fwh_config_t *fwh_add_config(fwh_image_t *image, const char *name, const char *loads);
FWH_INTERNAL fwh_finding_t *fwh_add_finding(fwh_image_t *image, int code, const char *where, const char *evidence);
FWH_INTERNAL void fwh_check_u32(fwh_checksum_t *check, uint32_t expected, uint32_t computed, int accept_inverted);

FWH_INTERNAL int fwh_probe_uimage(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_trx(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_fwtool(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_safeloader(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_hdr1(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_npk(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_chk(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_pak(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_android(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_probe_seama(const unsigned char *buf, size_t buf_len, size_t offset);
FWH_INTERNAL int fwh_parse_android(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_seama(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_probe_fdt(const unsigned char *buf, size_t buf_len, size_t offset);

FWH_INTERNAL int fwh_parse_uimage(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_trx(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_fwtool(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_safeloader(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_hdr1(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_npk(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_chk(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_pak(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_fit(fwh_image_t *image, size_t offset);
FWH_INTERNAL int fwh_parse_dtb(fwh_image_t *image, size_t offset);

#endif
