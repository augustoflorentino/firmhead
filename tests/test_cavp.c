#include "firmhead/firmhead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int unhex(const char *text, unsigned char *out, size_t cap)
{
    size_t n = strlen(text) / 2, i;
    unsigned v;

    if (n > cap)
        return -1;
    for (i = 0; i < n; i++) {
        if (sscanf(text + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return (int)n;
}

static int run(const char *path, const char *algo, size_t *out_count)
{
    static char line[1 << 17];
    static unsigned char msg[1 << 16];
    unsigned char expected[FWH_DIGEST_MAX], digest[FWH_DIGEST_MAX];
    size_t len = 0, digest_len;
    int failures = 0, msg_len = 0;
    FILE *f = fopen(path, "r");

    if (f == NULL)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "Len = ", 6) == 0) {
            len = (size_t)strtoul(line + 6, NULL, 10) / 8;
        } else if (strncmp(line, "Msg = ", 6) == 0) {
            msg_len = unhex(line + 6, msg, sizeof(msg));
        } else if (strncmp(line, "MD = ", 5) == 0) {
            if (msg_len < 0 || unhex(line + 5, expected, sizeof(expected)) < 0)
                return -1;
            fwh_digest(algo, msg, len, digest, &digest_len);
            failures += memcmp(digest, expected, digest_len) != 0;
            (*out_count)++;
        }
    }
    fclose(f);
    return failures;
}

int main(int argc, char **argv)
{
    static const char *const algos[][2] = {{"SHA1", "sha1"}, {"SHA256", "sha256"}, {"SHA384", "sha384"},
                                           {"SHA512", "sha512"}};
    static const char *const kinds[] = {"ShortMsg", "LongMsg"};
    char path[1024];
    size_t i, k, count;
    int failures = 0, result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s shabytetestvectors-dir\n", argv[0]);
        return 2;
    }
    for (i = 0; i < 4; i++)
        for (k = 0; k < 2; k++) {
            count = 0;
            snprintf(path, sizeof(path), "%s/%s%s.rsp", argv[1], algos[i][0], kinds[k]);
            result = run(path, algos[i][1], &count);
            printf("%-8s %-9s %4zu vectors, %d failures\n", algos[i][0], kinds[k], count, result);
            failures += result != 0;
        }
    return failures ? 1 : 0;
}
