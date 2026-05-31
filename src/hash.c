#include "firmhead/firmhead.h"
#include "internal.h"
#include "crc_table.h"

#include <string.h>

uint32_t fwh_crc32(uint32_t crc, const unsigned char *data, size_t data_len)
{
    crc = ~crc;
    while (data_len >= 8) {
        uint32_t lo = crc ^ ((uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 |
                             (uint32_t)data[3] << 24);
        uint32_t hi = (uint32_t)data[4] | (uint32_t)data[5] << 8 | (uint32_t)data[6] << 16 |
                      (uint32_t)data[7] << 24;
        crc = fwh_crc_table[7][lo & 0xFF] ^ fwh_crc_table[6][(lo >> 8) & 0xFF] ^
              fwh_crc_table[5][(lo >> 16) & 0xFF] ^ fwh_crc_table[4][lo >> 24] ^
              fwh_crc_table[3][hi & 0xFF] ^ fwh_crc_table[2][(hi >> 8) & 0xFF] ^
              fwh_crc_table[1][(hi >> 16) & 0xFF] ^ fwh_crc_table[0][hi >> 24];
        data += 8;
        data_len -= 8;
    }
    while (data_len--)
        crc = fwh_crc_table[0][(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

uint32_t fwh_netgear_sum(const unsigned char *data, size_t data_len)
{
    uint32_t c0 = 0, c1 = 0, b;
    size_t i;

    for (i = 0; i < data_len; i++) {
        c0 += data[i];
        c1 += c0;
    }
    b = (c0 & 0xFFFF) + (c0 >> 16);
    c0 = ((b >> 16) + b) & 0xFFFF;
    b = (c1 & 0xFFFF) + (c1 >> 16);
    c1 = ((b >> 16) + b) & 0xFFFF;
    return (c1 << 16) | c0;
}

#define FWH_ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FWH_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define FWH_ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

typedef struct {
    uint32_t h[8];
    uint64_t h64[8];
    unsigned char block[128];
    size_t used;
    uint64_t total;
    size_t block_len;
    void (*compress)(void *state, const unsigned char *block);
} fwh_hash_t;

static uint32_t fwh_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t fwh_be32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static uint64_t fwh_be64(const unsigned char *p)
{
    return (uint64_t)fwh_be32(p) << 32 | fwh_be32(p + 4);
}

static const uint32_t fwh_md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const unsigned char fwh_md5_r[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                            5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static void fwh_md5_compress(void *state, const unsigned char *block)
{
    uint32_t *h = ((fwh_hash_t *)state)->h;
    uint32_t w[16], a = h[0], b = h[1], c = h[2], d = h[3], f, t;
    int i, g;

    for (i = 0; i < 16; i++)
        w[i] = fwh_le32(block + 4 * i);
    for (i = 0; i < 64; i++) {
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) & 15;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) & 15;
        }
        t = d;
        d = c;
        c = b;
        b = b + FWH_ROL(a + f + fwh_md5_k[i] + w[g], fwh_md5_r[i]);
        a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

#define FWH_SHA1_W(i) (w[(i) & 15] = FWH_ROL(w[((i) + 13) & 15] ^ w[((i) + 8) & 15] ^ w[((i) + 2) & 15] ^ w[(i) & 15], 1))
#define FWH_SHA1_ROUND(a, b, c, d, e, f, k, x)                                                               \
    do {                                                                                                   \
        e += FWH_ROL(a, 5) + (f) + (k) + (x);                                                              \
        b = FWH_ROL(b, 30);                                                                                \
    } while (0)
#define FWH_SHA1_FIVE(f, k, x, i)                                                                          \
    do {                                                                                                   \
        FWH_SHA1_ROUND(a, b, c, d, e, f(b, c, d), k, x(i));                                                \
        FWH_SHA1_ROUND(e, a, b, c, d, f(a, b, c), k, x(i + 1));                                            \
        FWH_SHA1_ROUND(d, e, a, b, c, f(e, a, b), k, x(i + 2));                                            \
        FWH_SHA1_ROUND(c, d, e, a, b, f(d, e, a), k, x(i + 3));                                            \
        FWH_SHA1_ROUND(b, c, d, e, a, f(c, d, e), k, x(i + 4));                                            \
    } while (0)
#define FWH_SHA1_CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define FWH_SHA1_PARITY(x, y, z) ((x) ^ (y) ^ (z))
#define FWH_SHA1_MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define FWH_SHA1_LOAD(i) (w[i])

static void fwh_sha1_compress(void *state, const unsigned char *block)
{
    uint32_t *h = ((fwh_hash_t *)state)->h;
    uint32_t w[16], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    int i;

    for (i = 0; i < 16; i++)
        w[i] = fwh_be32(block + 4 * i);
    for (i = 0; i < 15; i += 5)
        FWH_SHA1_FIVE(FWH_SHA1_CH, 0x5A827999u, FWH_SHA1_LOAD, i);
    FWH_SHA1_ROUND(a, b, c, d, e, FWH_SHA1_CH(b, c, d), 0x5A827999u, w[15]);
    FWH_SHA1_ROUND(e, a, b, c, d, FWH_SHA1_CH(a, b, c), 0x5A827999u, FWH_SHA1_W(16));
    FWH_SHA1_ROUND(d, e, a, b, c, FWH_SHA1_CH(e, a, b), 0x5A827999u, FWH_SHA1_W(17));
    FWH_SHA1_ROUND(c, d, e, a, b, FWH_SHA1_CH(d, e, a), 0x5A827999u, FWH_SHA1_W(18));
    FWH_SHA1_ROUND(b, c, d, e, a, FWH_SHA1_CH(c, d, e), 0x5A827999u, FWH_SHA1_W(19));
    for (i = 20; i < 40; i += 5)
        FWH_SHA1_FIVE(FWH_SHA1_PARITY, 0x6ED9EBA1u, FWH_SHA1_W, i);
    for (; i < 60; i += 5)
        FWH_SHA1_FIVE(FWH_SHA1_MAJ, 0x8F1BBCDCu, FWH_SHA1_W, i);
    for (; i < 80; i += 5)
        FWH_SHA1_FIVE(FWH_SHA1_PARITY, 0xCA62C1D6u, FWH_SHA1_W, i);
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

static const uint32_t fwh_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define FWH_SHA256_ROUND(a, b, c, d, e, f, g, h, i)                                                          \
    do {                                                                                                      \
        uint32_t t1 = h + (FWH_ROR(e, 6) ^ FWH_ROR(e, 11) ^ FWH_ROR(e, 25)) + (g ^ (e & (f ^ g))) +           \
                      fwh_sha256_k[i] + w[i];                                                                 \
        d += t1;                                                                                              \
        h = t1 + (FWH_ROR(a, 2) ^ FWH_ROR(a, 13) ^ FWH_ROR(a, 22)) + ((a & b) | (c & (a | b)));               \
    } while (0)

static void fwh_sha256_compress(void *state, const unsigned char *block)
{
    uint32_t *st = ((fwh_hash_t *)state)->h;
    uint32_t w[64], s0, s1, a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = fwh_be32(block + 4 * i);
    for (; i < 64; i++) {
        s0 = FWH_ROR(w[i - 15], 7) ^ FWH_ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = FWH_ROR(w[i - 2], 17) ^ FWH_ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (i = 0; i < 64; i += 8) {
        FWH_SHA256_ROUND(a, b, c, d, e, f, g, h, i);
        FWH_SHA256_ROUND(h, a, b, c, d, e, f, g, i + 1);
        FWH_SHA256_ROUND(g, h, a, b, c, d, e, f, i + 2);
        FWH_SHA256_ROUND(f, g, h, a, b, c, d, e, i + 3);
        FWH_SHA256_ROUND(e, f, g, h, a, b, c, d, i + 4);
        FWH_SHA256_ROUND(d, e, f, g, h, a, b, c, i + 5);
        FWH_SHA256_ROUND(c, d, e, f, g, h, a, b, i + 6);
        FWH_SHA256_ROUND(b, c, d, e, f, g, h, a, i + 7);
    }
    st[0] += a, st[1] += b, st[2] += c, st[3] += d, st[4] += e, st[5] += f, st[6] += g, st[7] += h;
}

static const uint64_t fwh_sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static void fwh_sha512_compress(void *state, const unsigned char *block)
{
    uint64_t *h = ((fwh_hash_t *)state)->h64;
    uint64_t w[80], v[8], s0, s1, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = fwh_be64(block + 8 * i);
    for (; i < 80; i++) {
        s0 = FWH_ROR64(w[i - 15], 1) ^ FWH_ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        s1 = FWH_ROR64(w[i - 2], 19) ^ FWH_ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, h, sizeof(v));
    for (i = 0; i < 80; i++) {
        s1 = FWH_ROR64(v[4], 14) ^ FWH_ROR64(v[4], 18) ^ FWH_ROR64(v[4], 41);
        t1 = v[7] + s1 + ((v[4] & v[5]) ^ (~v[4] & v[6])) + fwh_sha512_k[i] + w[i];
        s0 = FWH_ROR64(v[0], 28) ^ FWH_ROR64(v[0], 34) ^ FWH_ROR64(v[0], 39);
        t2 = s0 + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof(v[0]));
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
        h[i] += v[i];
}

static void fwh_hash_update(fwh_hash_t *hs, const unsigned char *data, size_t data_len)
{
    hs->total += data_len;
    while (data_len > 0) {
        size_t take = hs->block_len - hs->used;

        if (take > data_len)
            take = data_len;
        if (hs->used == 0 && take == hs->block_len) {
            hs->compress(hs, data);
        } else {
            memcpy(hs->block + hs->used, data, take);
            hs->used += take;
            if (hs->used == hs->block_len) {
                hs->compress(hs, hs->block);
                hs->used = 0;
            }
        }
        data += take;
        data_len -= take;
    }
}

static void fwh_hash_pad(fwh_hash_t *hs, int little_endian)
{
    size_t length_bytes = hs->block_len == 128 ? 16 : 8;
    uint64_t bits = hs->total * 8;
    int i;

    hs->block[hs->used++] = 0x80;
    if (hs->used > hs->block_len - length_bytes) {
        memset(hs->block + hs->used, 0, hs->block_len - hs->used);
        hs->compress(hs, hs->block);
        hs->used = 0;
    }
    memset(hs->block + hs->used, 0, hs->block_len - hs->used);
    for (i = 0; i < 8; i++) {
        unsigned char byte = (unsigned char)(bits >> (8 * i));

        if (little_endian)
            hs->block[hs->block_len - 8 + i] = byte;
        else
            hs->block[hs->block_len - 1 - i] = byte;
    }
    hs->compress(hs, hs->block);
}

static const uint32_t fwh_init_md5[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
static const uint32_t fwh_init_sha1[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
static const uint32_t fwh_init_sha256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
static const uint64_t fwh_init_sha384[8] = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
                                            0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
                                            0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
static const uint64_t fwh_init_sha512[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                                            0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                                            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static int fwh_hash_setup(fwh_hash_t *hs, const char *algorithm, size_t *out_len)
{
    memset(hs, 0, sizeof(*hs));
    hs->block_len = 64;
    if (strcmp(algorithm, "md5") == 0) {
        memcpy(hs->h, fwh_init_md5, sizeof(fwh_init_md5));
        hs->compress = fwh_md5_compress;
        *out_len = 16;
    } else if (strcmp(algorithm, "sha1") == 0) {
        memcpy(hs->h, fwh_init_sha1, sizeof(fwh_init_sha1));
        hs->compress = fwh_sha1_compress;
        *out_len = 20;
    } else if (strcmp(algorithm, "sha256") == 0) {
        memcpy(hs->h, fwh_init_sha256, sizeof(fwh_init_sha256));
        hs->compress = fwh_sha256_compress;
        *out_len = 32;
    } else if (strcmp(algorithm, "sha384") == 0 || strcmp(algorithm, "sha512") == 0) {
        int is384 = algorithm[3] == '3';

        memcpy(hs->h64, is384 ? fwh_init_sha384 : fwh_init_sha512, sizeof(fwh_init_sha512));
        hs->compress = fwh_sha512_compress;
        hs->block_len = 128;
        *out_len = is384 ? 48 : 64;
    } else {
        return FWH_ERR_ARG;
    }
    return FWH_OK;
}

static void fwh_hash_output(const fwh_hash_t *hs, unsigned char *out, size_t len, int little_endian)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (hs->block_len == 128)
            out[i] = (unsigned char)(hs->h64[i / 8] >> (56 - 8 * (i % 8)));
        else if (little_endian)
            out[i] = (unsigned char)(hs->h[i / 4] >> (8 * (i % 4)));
        else
            out[i] = (unsigned char)(hs->h[i / 4] >> (24 - 8 * (i % 4)));
    }
}

FWH_INTERNAL int fwh_digest2(const char *algorithm, const unsigned char *a, size_t a_len, const unsigned char *b, size_t b_len,
                unsigned char *out_digest, size_t *out_digest_len)
{
    fwh_hash_t hs;
    size_t len;
    int little_endian;

    if (algorithm == NULL || out_digest == NULL || (a == NULL && a_len) || (b == NULL && b_len))
        return FWH_ERR_ARG;
    if (strcmp(algorithm, "crc32") == 0) {
        uint32_t crc = fwh_crc32(fwh_crc32(0, a, a_len), b, b_len);

        out_digest[0] = (unsigned char)(crc >> 24);
        out_digest[1] = (unsigned char)(crc >> 16);
        out_digest[2] = (unsigned char)(crc >> 8);
        out_digest[3] = (unsigned char)crc;
        if (out_digest_len)
            *out_digest_len = 4;
        return FWH_OK;
    }
    if (fwh_hash_setup(&hs, algorithm, &len) != FWH_OK)
        return FWH_ERR_ARG;
    little_endian = strcmp(algorithm, "md5") == 0;
    fwh_hash_update(&hs, a, a_len);
    fwh_hash_update(&hs, b, b_len);
    fwh_hash_pad(&hs, little_endian);
    fwh_hash_output(&hs, out_digest, len, little_endian);
    if (out_digest_len)
        *out_digest_len = len;
    return FWH_OK;
}

FWH_INTERNAL int fwh_digest_parts(const char *algorithm, const unsigned char *const *data, const size_t *lens, size_t n,
                                  unsigned char *out_digest)
{
    fwh_hash_t hs;
    size_t len, i;
    int little_endian;

    if (fwh_hash_setup(&hs, algorithm, &len) != FWH_OK)
        return FWH_ERR_ARG;
    little_endian = strcmp(algorithm, "md5") == 0;
    for (i = 0; i < n; i++)
        fwh_hash_update(&hs, data[i], lens[i]);
    fwh_hash_pad(&hs, little_endian);
    fwh_hash_output(&hs, out_digest, len, little_endian);
    return FWH_OK;
}

int fwh_digest(const char *algorithm, const unsigned char *data, size_t data_len, unsigned char *out_digest,
               size_t *out_digest_len)
{
    return fwh_digest2(algorithm, data, data_len, NULL, 0, out_digest, out_digest_len);
}
