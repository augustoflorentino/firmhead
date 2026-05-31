#define FWH_IMPLEMENTATION
#include "firmhead/firmhead.h"

int main(void)
{
    static const unsigned char header[64] = {0x27, 0x05, 0x19, 0x56};
    uint64_t formats = 1;
    fwh_image_t *image = NULL;
    size_t error_at = 0;
    int status = fwh_probe(header, sizeof(header), 0, &formats);

    if (status != FWH_OK || formats != 0 || fwh_crc32(0, (const unsigned char *)"123456789", 9) != 0xCBF43926u)
        return 1;
    status = fwh_open(header, sizeof(header), 0, FWH_FMT_UIMAGE, NULL, &image, &error_at);
    return status == FWH_ERR_DAMAGED && image == NULL && error_at == 4 ? 0 : 1;
}
