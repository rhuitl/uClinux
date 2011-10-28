#pragma once

#include <stdlib.h>

int decode_jpeg(void* jpeg_data, size_t jpeg_sz, int scale_denom,
                unsigned char** img, int* width, int* height, int* comps);
int write_pgm(const char* filename, unsigned char* data, int width, int height);
