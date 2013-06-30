/*
This file is part of ipcamd, an embedded web server for IP cameras.

Copyright (c) 2011-2013, Robert Huitl <robert@huitl.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "motion.h"
#include "profiling.h"
#include "jpegdecode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned short pixel_type;
static pixel_type img_ref[640*480/8/8];
static const int w = 10;     // in percent
static int g_width, g_height;
static int thresh = 3000;    // mean absolute distance * 1000

#define REF_SCALE       100
#define REF_SCALE_ROUND  50

void detect_motion(unsigned char* img, int width, int height)
{
	PROFILE_BEGIN(motion);

	static char initialized = 0;
	if(!initialized) {
		for(int i=0; i<width*height; i++)
			img_ref[i] = img[i]*REF_SCALE;
		//memcpy(img_ref, img, width*height);
		initialized = 1;
	}

	g_width = width;
	g_height = height;

	unsigned int sad = 0;
	pixel_type* img_ref_p = img_ref;
	for(int i=0; i<width*height; i++) {
		int diff = (int)(*img_ref_p+REF_SCALE_ROUND)/REF_SCALE - (int)*img;
		//if(i >= 30*80+40 && i < 30*80+45)
		//	printf("%d ", diff);
		sad += abs(diff);
		*img_ref_p = ((*img_ref_p * (100-w)) + (*img*100 * w) + 50) / 100;
		img_ref_p++;
		img++;
	}
	printf("\n");

	unsigned int mad = sad / width * 1000 / height;
	if(mad > thresh) {
		printf("MOTION (sad = %d, mad = %d / 1000\n", sad, mad);
	}

	PROFILE_END(motion)
}

void save_reference_image(const char* fn)
{
	write_pgm_scaled(fn, img_ref, g_width, g_height, REF_SCALE);
}
