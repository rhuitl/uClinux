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
