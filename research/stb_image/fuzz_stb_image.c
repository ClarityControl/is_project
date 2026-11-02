#include <stddef.h>
#include <stdint.h>
#include <limits.h>

/* Keep individual decoded images bounded in this local research harness. */
#define STBI_MAX_DIMENSIONS 8192
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int width = 0;
    int height = 0;
    int source_channels = 0;
    int is_hdr;
    int is_16_bit;
    int decoded_size = 0;
    int frame_count = 0;
    int *frame_delays = NULL;
    unsigned char *pixels;
    unsigned char *gif_pixels;
    stbi_us *pixels16;
    float *pixelsf;
    char *zlib_pixels;

    if (size == 0 || size > INT_MAX) {
        return 0;
    }

    /* Exercise header inspection and the common decoder paths. */
    (void)stbi_info_from_memory(data, (int)size,
                                &width, &height, &source_channels);
    is_hdr = stbi_is_hdr_from_memory(data, (int)size);
    is_16_bit = stbi_is_16_bit_from_memory(data, (int)size);

    /* Exercise native output and requested-channel conversion. */
    pixels = stbi_load_from_memory(data, (int)size,
                                   &width, &height, &source_channels, 0);
    stbi_image_free(pixels);

    pixels = stbi_load_from_memory(data, (int)size,
                                   &width, &height, &source_channels, 4);
    stbi_image_free(pixels);

    /* The GIF sequence API exercises animated-frame composition. */
    gif_pixels = stbi_load_gif_from_memory(data, (int)size, &frame_delays,
                                           &width, &height, &frame_count,
                                           &source_channels, 4);
    stbi_image_free(gif_pixels);
    stbi_image_free(frame_delays);

    if (is_16_bit) {
        pixels16 = stbi_load_16_from_memory(data, (int)size,
                                            &width, &height, &source_channels, 4);
        stbi_image_free(pixels16);
    }

    if (is_hdr) {
        pixelsf = stbi_loadf_from_memory(data, (int)size,
                                         &width, &height, &source_channels, 4);
        stbi_image_free(pixelsf);
    }

    /* The standalone zlib helpers are public parser entry points too. Keep
       their inputs small because they can expand compressed data substantially. */
    if (size <= 4096) {
        zlib_pixels = stbi_zlib_decode_malloc_guesssize((const char *)data,
                                                       (int)size, 1,
                                                       &decoded_size);
        stbi_image_free(zlib_pixels);

        zlib_pixels = stbi_zlib_decode_noheader_malloc((const char *)data,
                                                       (int)size,
                                                       &decoded_size);
        stbi_image_free(zlib_pixels);
    }

    return 0;
}
