#include "firmhead/firmhead.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fwh_image_t *image;
    size_t error_at, i;
    unsigned formats;
    int format;

    if (fwh_probe(data, size, 0, &formats) != FWH_OK)
        return 0;
    for (format = 1; format < FWH_FMT_COUNT; format++) {
        image = NULL;
        if (fwh_open(data, size, 0, format, NULL, NULL, NULL, &image, &error_at) != FWH_OK)
            continue;
        fwh_audit(image);
        for (i = 0; i < fwh_part_count(image); i++)
            if (fwh_part_get(image, i)->offset + fwh_part_get(image, i)->size > size)
                __builtin_trap();
        fwh_image_destroy(image);
    }
    return 0;
}
