#include "config.h"
#include "jpegdecode.h"

#include <stdio.h>
#include <jpeglib.h>
#include <errno.h>
#include <string.h>

#if JPEG_LIB_VERSION > 62
#	define HAVE_JPEG_MEM_SRC
#endif

#ifndef HAVE_JPEG_MEM_SRC
// From http://stackoverflow.com/questions/5280756/libjpeg-ver-6b-jpeg-stdio-src-vs-jpeg-mem-src
// An implementation of jpeg_mem_src() for libjpeg 6b and earlier.

/* Read JPEG image from a memory segment */
static void init_source (j_decompress_ptr cinfo)
{ }

static boolean fill_input_buffer (j_decompress_ptr cinfo)
{
	printf("BUG: fill_input_buffer\n");
	exit(1);
}

static void skip_input_data (j_decompress_ptr cinfo, long num_bytes)
{
    struct jpeg_source_mgr* src = (struct jpeg_source_mgr*) cinfo->src;

    if (num_bytes > 0) {
        src->next_input_byte += (size_t) num_bytes;
        src->bytes_in_buffer -= (size_t) num_bytes;
    }
}

static void term_source (j_decompress_ptr cinfo)
{ }

static void jpeg_mem_src (j_decompress_ptr cinfo, void* buffer, long nbytes)
{
	struct jpeg_source_mgr* src;

	if(cinfo->src == NULL) {   /* first time for this JPEG object? */
		cinfo->src = (struct jpeg_source_mgr *)
		(*cinfo->mem->alloc_small)(
			(j_common_ptr)cinfo, JPOOL_PERMANENT, sizeof(struct jpeg_source_mgr)
		);
	}

	src = (struct jpeg_source_mgr*)cinfo->src;
	src->init_source = init_source;
	src->fill_input_buffer = fill_input_buffer;
	src->skip_input_data = skip_input_data;
	src->resync_to_restart = jpeg_resync_to_restart; /* use default method */
	src->term_source = term_source;
	src->bytes_in_buffer = nbytes;
	src->next_input_byte = (JOCTET*)buffer;
}
#endif

int decode_jpeg(void* jpeg_data, size_t jpeg_sz, int scale_denom,
                unsigned char** img, int* width, int* height, int* comps)
{
	struct jpeg_decompress_struct cinfo;
	struct jpeg_error_mgr jerr;
	*img = NULL;

	cinfo.err = jpeg_std_error(&jerr);            // standard error handler
	jpeg_create_decompress(&cinfo);               // setup decompression
	jpeg_mem_src(&cinfo, jpeg_data, jpeg_sz);     // read data from memory
	jpeg_read_header(&cinfo, TRUE);

/*	printf( "JPEG File Information: \n" );
	printf( "Image width and height: %d pixels and %d pixels.\n", cinfo.image_width, cinfo.image_height );
	printf( "Color components per pixel: %d.\n", cinfo.num_components );
	printf( "Color space: %d.\n", cinfo.jpeg_color_space );*/

	// decompress as grayscale image, possibly subsampled
	cinfo.out_color_space = JCS_GRAYSCALE;
	cinfo.scale_num = 1;
	cinfo.scale_denom = scale_denom;

	cinfo.dct_method = JDCT_DEFAULT;

	// start decompression. this will set output_width and output_height
	// according to the scaling parameters.
	jpeg_start_decompress(&cinfo);

/*	printf("Output image: %d x %d x %d\n",
		cinfo.output_width, cinfo.output_height, cinfo.output_components);
	printf("Recommended height: %d\n", cinfo.rec_outbuf_height);*/
	*width  = cinfo.output_width;
	*height = cinfo.output_height;
	*comps  = cinfo.output_components;

	// allocate memory for decoded image
	unsigned char* raw_image = (unsigned char*)
		malloc(cinfo.output_width*cinfo.output_height*cinfo.num_components);

	// read scanlines to buffer
	JSAMPROW row_ptr[1];
	unsigned long location = 0;
	while(cinfo.output_scanline < cinfo.output_height) {
		row_ptr[0] = &raw_image[location];
		jpeg_read_scanlines(&cinfo, row_ptr, 1);
		location += cinfo.output_width*cinfo.output_components;
	}

	// clean up
	jpeg_finish_decompress(&cinfo);
	jpeg_destroy_decompress(&cinfo);

	*img = raw_image;

	return 0;
}

int write_pgm(const char* filename, unsigned char* data, int width, int height)
{
	FILE* f = fopen(filename, "wb");
	if(!f) {
		printf("Cannot open file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	fprintf(f, "P5\n%d %d\n255\n", width, height);
	for(int i=0; i<width*height; i++)
		fputc(*data++, f);
	fclose(f);
	return 0;
}
