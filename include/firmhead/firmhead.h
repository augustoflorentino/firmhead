#ifndef FIRMHEAD_H
#define FIRMHEAD_H

#include <stddef.h>
#include <stdint.h>

#if defined(FWH_STATIC) && defined(__GNUC__)
#define FWH_API static __attribute__((unused))
#elif defined(FWH_STATIC)
#define FWH_API static
#elif defined(_WIN32) && defined(FWH_BUILD_SHARED)
#define FWH_API __declspec(dllexport)
#elif defined(_WIN32) && defined(FWH_SHARED)
#define FWH_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(FWH_BUILD_SHARED)
#define FWH_API __attribute__((visibility("default")))
#else
#define FWH_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FWH_OK 0
#define FWH_ERR_ARG 1
#define FWH_ERR_NOMEM 2
#define FWH_ERR_FORMAT 3
#define FWH_ERR_TRUNCATED 4
#define FWH_ERR_DAMAGED 5
#define FWH_ERR_LIMIT 6

#define FWH_FMT_NONE 0
#define FWH_FMT_UIMAGE 1
#define FWH_FMT_TRX 2
#define FWH_FMT_FWTOOL 3
#define FWH_FMT_SAFELOADER 4
#define FWH_FMT_HDR1 5
#define FWH_FMT_NPK 6
#define FWH_FMT_CHK 7
#define FWH_FMT_PAK 8
#define FWH_FMT_FIT 9
#define FWH_FMT_DTB 10
#define FWH_FMT_ANDROID 11
#define FWH_FMT_SEAMA 12
#define FWH_FMT_TPLINK 13
#define FWH_FMT_UBNT 14
#define FWH_FMT_COUNT 15
#define FWH_OPEN_AUDIT 0x1u
#define FWH_OPEN_STRICT 0x2u
#define FWH_FMT_BIT(format) ((uint64_t)1 << (format))

#define FWH_ROLE_OTHER 0
#define FWH_ROLE_KERNEL 1
#define FWH_ROLE_ROOTFS 2
#define FWH_ROLE_FDT 3
#define FWH_ROLE_RAMDISK 4
#define FWH_ROLE_FIRMWARE 5
#define FWH_ROLE_SCRIPT 6
#define FWH_ROLE_FILES 7
#define FWH_ROLE_SIGNATURE 8
#define FWH_ROLE_METADATA 9

#define FWH_SCOPE_HEADER 1
#define FWH_SCOPE_DATA 2
#define FWH_SCOPE_PART 3
#define FWH_SCOPE_WHOLE 4
#define FWH_SCOPE_IMAGE 5
#define FWH_SCOPE_CONFIGURATION 6

#define FWH_CHECK_OK 1
#define FWH_CHECK_BAD 2
#define FWH_CHECK_UNVERIFIABLE 3

#define FWH_FIND_WEAK 1
#define FWH_FIND_IMAGES_ONLY 2
#define FWH_FIND_PARTIAL_CONFIG 3
#define FWH_FIND_OPTIONAL_KEYS 4
#define FWH_FIND_AMBIGUOUS_NODE 5

#define FWH_VERSION_MAJOR 3
#define FWH_VERSION_MINOR 0
#define FWH_VERSION_PATCH 0
#define FWH_VERSION_STRING "3.0.0"

#define FWH_DIGEST_MAX 64

typedef struct fwh_image fwh_image_t;

typedef void *(*fwh_alloc_fn)(void *ctx, size_t size);
typedef void (*fwh_free_fn)(void *ctx, void *ptr);

typedef struct fwh_allocator {
    fwh_alloc_fn alloc;
    fwh_free_fn free;
    void *ctx;
} fwh_allocator_t;

typedef struct fwh_part {
    const char *name;
    uint64_t offset;
    uint64_t size;
    int role;
    const char *compression;
    const char *detail;
} fwh_part_t;

typedef struct fwh_meta {
    const char *key;
    const char *value;
} fwh_meta_t;

typedef struct fwh_checksum {
    const char *algorithm;
    int scope;
    const char *covers;
    int state;
    uint64_t offset;
    uint64_t size;
    size_t digest_len;
    unsigned char expected[FWH_DIGEST_MAX];
    unsigned char computed[FWH_DIGEST_MAX];
} fwh_checksum_t;

typedef struct fwh_signature {
    const char *node;
    const char *algorithm;
    unsigned bits;
    const char *key_hint;
    int scope;
    const char *covers;
    uint64_t value_offset;
    uint64_t value_size;
    uint64_t signed_offset;
    uint64_t signed_size;
} fwh_signature_t;

typedef struct fwh_key {
    const char *node;
    const char *algorithm;
    unsigned bits;
    const char *key_hint;
    const char *required;
} fwh_key_t;

typedef struct fwh_config {
    const char *name;
    const char *loads;
} fwh_config_t;

typedef struct fwh_finding {
    int code;
    const char *where;
    const char *evidence;
} fwh_finding_t;

typedef struct fwh_magic {
    int format;
    const unsigned char *bytes;
    size_t bytes_len;
    size_t at;
} fwh_magic_t;

FWH_API const fwh_magic_t *fwh_magics(size_t *out_count);
FWH_API int fwh_probe(const unsigned char *buf, size_t buf_len, size_t offset, uint64_t *out_formats);
FWH_API int fwh_open(const unsigned char *buf, size_t buf_len, size_t offset, int format, unsigned flags,
                     const fwh_allocator_t *allocator, fwh_image_t **out_image, size_t *out_error_at);
FWH_API void fwh_image_destroy(fwh_image_t *image);
FWH_API int fwh_image_format(const fwh_image_t *image);
FWH_API uint64_t fwh_image_offset(const fwh_image_t *image);
FWH_API uint64_t fwh_image_size(const fwh_image_t *image);
FWH_API const char *fwh_image_description(const fwh_image_t *image);
FWH_API int fwh_image_signed(const fwh_image_t *image);
FWH_API size_t fwh_part_count(const fwh_image_t *image);
FWH_API const fwh_part_t *fwh_part_get(const fwh_image_t *image, size_t index);
FWH_API const fwh_part_t *fwh_part_find(const fwh_image_t *image, const char *name);
FWH_API size_t fwh_meta_count(const fwh_image_t *image);
FWH_API const fwh_meta_t *fwh_meta_get(const fwh_image_t *image, size_t index);
FWH_API const char *fwh_meta_find(const fwh_image_t *image, const char *key);
FWH_API size_t fwh_checksum_count(const fwh_image_t *image);
FWH_API const fwh_checksum_t *fwh_checksum_get(const fwh_image_t *image, size_t index);
FWH_API size_t fwh_signature_count(const fwh_image_t *image);
FWH_API const fwh_signature_t *fwh_signature_get(const fwh_image_t *image, size_t index);
FWH_API size_t fwh_key_count(const fwh_image_t *image);
FWH_API const fwh_key_t *fwh_key_get(const fwh_image_t *image, size_t index);
FWH_API size_t fwh_config_count(const fwh_image_t *image);
FWH_API const fwh_config_t *fwh_config_get(const fwh_image_t *image, size_t index);
FWH_API int fwh_audit(fwh_image_t *image);
FWH_API size_t fwh_finding_count(const fwh_image_t *image);
FWH_API const fwh_finding_t *fwh_finding_get(const fwh_image_t *image, size_t index);

FWH_API uint32_t fwh_crc32(uint32_t crc, const unsigned char *data, size_t data_len);
FWH_API int fwh_digest(const char *algorithm, const unsigned char *data, size_t data_len,
                       unsigned char *out_digest, size_t *out_digest_len);
FWH_API uint32_t fwh_netgear_sum(const unsigned char *data, size_t data_len);

FWH_API const char *fwh_version(void);
FWH_API const char *fwh_strerror(int status);
FWH_API const char *fwh_format_name(int format);
FWH_API int fwh_format_from_name(const char *name);
FWH_API const char *fwh_role_name(int role);
FWH_API const char *fwh_scope_name(int scope);
FWH_API const char *fwh_check_name(int state);
FWH_API const char *fwh_finding_name(int code);

#ifdef __cplusplus
}
#endif

#endif
