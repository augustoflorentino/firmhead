#include "firmhead/firmhead.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fwh_image_t *image;
    size_t error_at, i;
    uint64_t formats;
    int format;

    if (fwh_probe(data, size, 0, &formats) != FWH_OK)
        return 0;
#ifdef FWH_FUZZ_FORMAT
    for (format = FWH_FUZZ_FORMAT; format == FWH_FUZZ_FORMAT; format++) {
#else
    for (format = 0; format < FWH_FMT_COUNT; format++) {
#endif
        image = NULL;
        if (fwh_open(data, size, 0, format, 0, NULL, &image, &error_at) != FWH_OK)
            continue;
        fwh_audit(image);
        for (i = 0; i < fwh_part_count(image); i++)
            if (fwh_part_get(image, i)->offset + fwh_part_get(image, i)->size > size)
                __builtin_trap();
        fwh_image_destroy(image);
    }
    return 0;
}
