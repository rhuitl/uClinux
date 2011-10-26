/*
 * File:         jpegview.c
 *
 * Description:  View jpegs on a frame buffer
 *
 * Modified:     Copyright 2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fb.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <setjmp.h>
#include <jpeglib.h>

unsigned char *framebase = 0;
unsigned long ScreenWidth, ScreenHeight;
unsigned long ImageWidth, ImageHeight;

//#define RGB(r,g,b) (((b&0x1f)<<11)|((g&0x3f)<<5)|(r&0x1f))
//#define RGB(r,g,b) ~((((b&0xf8)<<8)|((g&0xfc)<<3)|(r>>3)))
#define RGB(r,g,b) ((((r&0xf8)<<8)|((g&0xfc)<<3)|(b>>3)))

struct my_error_mgr {
	struct jpeg_error_mgr pub;/* "public" fields */
	
	jmp_buf setjmp_buffer;/* for return to caller */
};

typedef struct my_error_mgr * my_error_ptr;

/*
 * Here's the routine that will replace the standard error_exit method:
 */

void my_error_exit (j_common_ptr cinfo)
{
	/* cinfo->err really points to a my_error_mgr struct, so coerce pointer */
	my_error_ptr myerr = (my_error_ptr) cinfo->err;
	
	/* Always display the message. */
	/* We could postpone this until after returning, if we chose. */
	(*cinfo->err->output_message) (cinfo);
	
	/* Return control to the setjmp point */
	longjmp(myerr->setjmp_buffer, 1);
}

void put_scanline_someplace_noscale(unsigned char *buffer, int row_width, unsigned long row)
{
	unsigned short *pD;
	unsigned char *pS;
	unsigned char r, g, b;
	unsigned long startx=0, starty=0;


	if(row >= ScreenHeight)
		return;

	if(ImageWidth < ScreenWidth)
		startx = (ScreenWidth - ImageWidth)/2;
	if(ImageHeight < ScreenHeight)
		starty = (ScreenHeight - ImageHeight)/2;

	pD = (unsigned short*)framebase + ((row+starty) * ScreenWidth);
	pS = buffer;

	while(startx--)
		pD++;
	while(row_width--)
       	{
		if(row_width < ScreenWidth)
	       	{
			r = *pS++;
			g = *pS++;
			b = *pS++;
			// *pD++ = ((r<<7)&0x7c00) | ((g<<2)&0x03e0) | ((b>>3)&0x001f) | 0x8000;
			*pD++   = RGB(r,g,b);
		}
	}
}

static unsigned long *ScaleTableX, *ScaleTableY;
static int FixScale = 1;

void put_scanline_someplace_scale(unsigned char *buffer, int row_width, unsigned long row)
{
	int i, y = -1;
	unsigned char *pS;
	unsigned short *pD, *pC;
	unsigned char r, g, b;
	unsigned long startx=0, starty=0;

	for(i=0; i<ImageHeight;i++)
       	{
       		if(ScaleTableY[i] == row)
       		{
			y = i;
			break;
		}
	}

	if(y != -1)
	{
		if(ImageWidth < ScreenWidth)
			startx = (ScreenWidth - ImageWidth)/2;
		if(ImageHeight < ScreenHeight)
			starty = (ScreenHeight - ImageHeight)/2;

		pD = (unsigned short*)framebase + ((y+starty) * ScreenWidth);
		while(startx--)
			pD++;
		for(i=0; i<ImageWidth; i++)
		{
			pS= buffer + (ScaleTableX[i]*3);
			if(pS > (buffer+row_width))
				break;
			r = *pS++;
			g = *pS++;
			b = *pS;
			// *pD++ = ((r<<7)&0x7c00) | ((g<<2)&0x03e0) | ((b>>3)&0x001f) | 0x8000;
			*pD++   = RGB(r,g,b);
		}

		pC = (unsigned short*)framebase + ((y+starty) * ScreenWidth);

		for(i=y+1; i<ImageHeight;i++)
		{
			if(ScaleTableY[i] == row)
		       	{
				pD = (unsigned short*)framebase + ((i+starty) * ScreenWidth);
				memcpy(pD, pC, ScreenWidth*2);
			}
			else if(ScaleTableX[i] > row)
				break;
		}
	}
}

unsigned long div45(unsigned long num1, unsigned long num2)
{
	if((num1%num2) > (num2/2))
		return num1/num2+1;
	else
		return num1/num2;
}

void CreateScaleTable(int src_width, int src_height)
{
	int i;
	ScaleTableX= malloc(ImageWidth * sizeof(unsigned long));
	ScaleTableY= malloc(ImageHeight * sizeof(unsigned long));

	for(i=ImageWidth-1; i>=0; i--)
	{
		ScaleTableX[i] = div45(i * src_width, ImageWidth);
	}

	for(i=ImageHeight-1; i>=0; i--)
       	{
		ScaleTableY[i] = div45(i * src_height, ImageHeight);
	}
}

void ReleaseScaleTable(void)
{
	if(ScaleTableX)
		free(ScaleTableX);
	if(ScaleTableY)
		free(ScaleTableY);
	ScaleTableX = ScaleTableY = 0;
}


int read_JPEG_file (char * filename)
{
	/* This struct contains the JPEG decompression parameters and pointers to
	 * working space (which is allocated as needed by the JPEG library).
	 */
	struct jpeg_decompress_struct cinfo;
	/* We use our private extension JPEG error handler.
	 * Note that this struct must live as long as the main JPEG parameter
	 * struct, to avoid dangling-pointer problems.
	 */
	struct my_error_mgr jerr;
	/* More stuff */
	FILE * infile;/* source file */
	JSAMPARRAY buffer;/* Output row buffer */
	int row_stride;/* physical row width in output buffer */
	
	/* In this example we want to open the input file before doing anything else,
	 * so that the setjmp() error recovery below can assume the file is open.
	 * VERY IMPORTANT: use "b" option to fopen() if you are on a machine that
	 * requires it in order to read binary files.
	 */
	
	if ((infile = fopen(filename, "rb")) == NULL) {
		fprintf(stderr, "can't open %s\n", filename);
		return 0;
	}

	/* Step 1: allocate and initialize JPEG decompression object */
	
	/* We set up the normal JPEG error routines, then override error_exit. */
	cinfo.err = jpeg_std_error(&jerr.pub);
	jerr.pub.error_exit = my_error_exit;
	/* Establish the setjmp return context for my_error_exit to use. */
	if (setjmp(jerr.setjmp_buffer)) {
		/* If we get here, the JPEG code has signaled an error.
		 * We need to clean up the JPEG object, close the input file, and return.
		 */
		jpeg_destroy_decompress(&cinfo);
		fclose(infile);
		return 0;
	}
	/* Now we can initialize the JPEG decompression object. */
	jpeg_create_decompress(&cinfo);
	
	/* Step 2: specify data source (eg, a file) */
	
	jpeg_stdio_src(&cinfo, infile);
	
	/* Step 3: read file parameters with jpeg_read_header() */
	
	(void) jpeg_read_header(&cinfo, TRUE);
	/* We can ignore the return value from jpeg_read_header since
	 *   (a) suspension is not possible with the stdio data source, and
	 *   (b) we passed TRUE to reject a tables-only JPEG file as an error.
	 * See libjpeg.doc for more info.
	 */
	
	/* Step 4: set parameters for decompression */
	
	/* In this example, we don't need to change any of the defaults set by
	 * jpeg_read_header(), so we do nothing here.
	 */
	
	/* Step 5: Start decompressor */
	(void) jpeg_start_decompress(&cinfo);
	/* We can ignore the return value since suspension is not possible
	 * with the stdio data source.
	 */
	
	/* We may need to do some setup of our own at this point before reading
	 * the data.  After jpeg_start_decompress() we have the correct scaled
	 * output image dimensions available, as well as the output colormap
	 * if we asked for color quantization.
	 * In this example, we need to make an output work buffer of the right size.
	 */ 
	/* JSAMPLEs per row in output buffer */
	row_stride = cinfo.output_width * cinfo.output_components;
	/* Make a one-row-high sample array that will go away when done with image */
	buffer = (*cinfo.mem->alloc_sarray)
		((j_common_ptr) &cinfo, JPOOL_IMAGE, row_stride, 1);
	
	/* Step 6: while (scan lines remain to be read) */
	/*           jpeg_read_scanlines(...); */
	
	/* Here we use the library's state variable cinfo.output_scanline as the
	 * loop counter, so that we don't have to keep track ourselves.
	 */

	ImageWidth = cinfo.output_width;
	ImageHeight = cinfo.output_height;
	if(FixScale)
       	{
		if(((double)ImageWidth/(double)ImageHeight) > ((double)ScreenWidth/(double)ScreenHeight))
	       	{
			ImageHeight = (unsigned long)((double)ImageHeight*(double)ScreenWidth/(double)ImageWidth);
			ImageWidth = ScreenWidth;
		}
		else
	       	{
			ImageWidth = (unsigned long)((double)ImageWidth*(double)ScreenHeight/(double)ImageHeight);
			ImageHeight = ScreenHeight;
		}
		CreateScaleTable(cinfo.output_width, cinfo.output_height);
		printf("ImageWidth=%ld ImageHeight=%ld\n", ImageWidth, ImageHeight);
	}

	while (cinfo.output_scanline < cinfo.output_height) {
		/* jpeg_read_scanlines expects an array of pointers to scanlines.
		 * Here the array is only one element long, but you could ask for
		 * more than one scanline at a time if that's more convenient.
		 */
		(void) jpeg_read_scanlines(&cinfo, buffer, 1);
		/* Assume put_scanline_someplace wants a pointer and sample count. */
		if(FixScale)
			put_scanline_someplace_scale(buffer[0], row_stride, cinfo.output_scanline-1);
		else
			put_scanline_someplace_noscale(buffer[0], row_stride, cinfo.output_scanline-1);
	}

	if(FixScale)
		ReleaseScaleTable();

	/* Step 7: Finish decompression */
	
	(void) jpeg_finish_decompress(&cinfo);
	/* We can ignore the return value since suspension is not possible
	 * with the stdio data source.
	 */
	
	/* Step 8: Release JPEG decompression object */
	
	/* This is an important step since it will release a good deal of memory. */
	jpeg_destroy_decompress(&cinfo);
	
	/* After finish_decompress, we can close the input file.
	 * Here we postpone it until after no more JPEG errors are possible,
	 * so as to simplify the setjmp error logic above.  (Actually, I don't
	 * think that jpeg_destroy can do an error exit, but why assume anything...)
	 */
	fclose(infile);
	
	/* At this point you may want to check to see whether any corrupt-data
	 * warnings occurred (test whether jerr.pub.num_warnings is nonzero).
	 */
	
	/* And we're done! */
	return 1;
}


int main(int argc, char **argv)
{
	int i, j;
	int fd = -1;
	int sec = 5;
	
	struct fb_var_screeninfo vi, initial_vi;

	if (argc < 2 )
	{
		printf("Usage: jpegview <-s[Seconds]> <-f|-o> file_1.jpg file_2.jpg ...\n"
			"\t-s[Seconds] : Time to show this picture\n"
			"\t-f : Fixed Scale \n"
			"\t-o : None-Fixed Scale\n");
		return -1;
	}

	fd = open("/dev/fb0", O_RDWR);
        if(fd < 0)
       	{
       		printf("cannot open /dev/fb0\n");
       		exit(0);
       	}

        ioctl(fd, FBIOGET_VSCREENINFO, &initial_vi);
        initial_vi.xoffset = initial_vi.yoffset = 0;

        ioctl(fd, FBIOGET_VSCREENINFO, &vi);
	printf("%d %d %d %d %d %d %d %d %d %d\n", vi.xres, vi.yres, vi.xres_virtual, vi.yres_virtual,
               vi.xoffset, vi.yoffset, vi.bits_per_pixel, vi.grayscale, vi.width, vi.height);

	//framebase = mmap(0, vi.xres * vi.yres*2, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        framebase = mmap(0, vi.xres * vi.yres*2, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        printf("framebase = %p err=%d\n", framebase, errno);
	if (framebase == MAP_FAILED)
	{
		printf("Error mmap frame buffer\n");
		return -1;
	}
	
	ScreenWidth = vi.xres;
	ScreenHeight = vi.yres;

	memset(framebase, 0x00, vi.xres*vi.yres*2);

	for(i=1;i<argc;i++)
       	{
		for(j=0; j<vi.xres*vi.yres; j++)
			((unsigned short*)framebase)[j] = 0x8000;

		if(argv[i][0] == '-')
	       	{
			switch(argv[i][1])
		       	{
			case 'F': case 'f':
				FixScale = 1;
				break;
			case 'O': case 'o':
				FixScale = 0;
				break;
			case 'S': case 's':
				sec = atoi (argv[i]+2);
				break;
			}
			continue;
	       	}
		printf("read %s %s\n", argv[i], read_JPEG_file(argv[i]) ? "OK" : "FAIL");
		sleep (sec);
       	}
	close(fd);
	return 0;
}
