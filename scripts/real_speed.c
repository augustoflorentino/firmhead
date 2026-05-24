#define _POSIX_C_SOURCE 200809L
#include "firmhead/firmhead.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    int a, r;

    for (a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        size_t len, err;
        unsigned char *buf;
        double best = 1e9, t;
        fwh_image_t *image;

        fseek(f, 0, SEEK_END);
        len = (size_t)ftell(f);
        fseek(f, 0, SEEK_SET);
        buf = malloc(len);
        if (fread(buf, 1, len, f) != len)
            return 2;
        fclose(f);
        for (r = 0; r < 20; r++) {
            image = NULL;
            t = now();
            fwh_open(buf, len, 0, FWH_FMT_NONE, NULL, &image, &err);
            fwh_audit(image);
            t = now() - t;
            if (t < best)
                best = t;
            fwh_image_destroy(image);
        }
        printf("%7.2f ms  %5.1f MiB  %s\n", best * 1000, len / 1048576.0, argv[a]);
        free(buf);
    }
    return 0;
}
