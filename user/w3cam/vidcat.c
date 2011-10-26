/*
 * vidcat.c
 *
 * Copyright (C) 1998 - 2001 Rasca, Berlin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>	/* gettimeofday() */
#include <fcntl.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/videodev.h>
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif
#ifdef HAVE_LIBPNG
#include <png.h>
#endif
#ifdef HAVE_LIBJPEG
#include <jpeglib.h>
#endif
#include "v4l.h"

#define DEF_WIDTH	320	/* default width */
#define DEF_HEIGHT	240	/* default height */

#define FMT_UNKNOWN		0
#define FMT_PPM			1
#define FMT_PGM			2
#define FMT_PNG			3
#define FMT_JPEG		4
#define FMT_YUV4MPEG	5

#define IN_TV			0
#define IN_COMPOSITE	1
#define IN_COMPOSITE2	2
#define IN_SVIDEO		3

#define NORM_PAL		0
#define NORM_NTSC		1
#define NORM_SECAM		2

#define QUAL_DEFAULT	80

char *basename (const char *s);

/* globals
 */
static int verbose = 0;

/*
 */
void
usage (char *pname)
{
	fprintf (stderr,
	"VidCat, Version %s\n"
	"Usage: %s <options>\n"
	" -b                          make a raw PPM instead of an ASCII one\n"
	" -d <device>                 video device (default: "VIDEO_DEV")\n"
	" -f {ppm|jpeg|png|yuv4mpeg}  output format of the image\n"
	" -g                          greayscale instead of color\n"
	" -i {tv|comp1|comp2|s-video} which input channel to use\n"
	" -l                          loop on, doesn't make sense in most cases\n"
	" -n {pal|ntsc|secam}         select video norm\n"
	" -o <file>                   write output to file instead of stdout\n"
	" -p c|g|y|Y                  videopalette to use\n"
	" -q <quality>                only for jpeg: quality setting (1-100,"
		" default: %d)\n"
	" -s NxN                      define size of the output image (default:"
		" %dx%d)\n"
	"Example: vidcat | xsetbg stdin\n",
		VERSION, (char*)basename(pname), QUAL_DEFAULT, DEF_WIDTH, DEF_HEIGHT);
	exit (1);
}

/*
 */
double
ms_time (void)
{
	static struct timeval tod;
	gettimeofday (&tod, NULL);
	return ((double)tod.tv_sec * 1000.0 + (double)tod.tv_usec / 1000.0);
	
}


/*
 * read rgb image from v4l device
 * return: mmap'ed buffer and size
 */
char *
get_image (int dev, int width, int height, int palette ,int *size)
{
	struct video_mbuf vid_buf;
	struct video_mmap vid_mmap;
	char *map, *convmap;
	int len;
	int bytes = 3;

	if (palette == VIDEO_PALETTE_GREY)
		bytes = 1;	/* bytes per pixel */

	if (ioctl (dev, VIDIOCGMBUF, &vid_buf) == -1) {
		/* to do a normal read()
		 */
		struct video_window vid_win;
		if (verbose) {
			fprintf (stderr, "using read()\n");
		}

		if (ioctl (dev, VIDIOCGWIN, &vid_win) != -1) {
			vid_win.width  = width;
			vid_win.height = height;
			if (ioctl (dev, VIDIOCSWIN, &vid_win) == -1) {
				perror ("ioctl(VIDIOCSWIN)");
				return (NULL);
			}
		}

		map = malloc (width * height * bytes);
		len = read (dev, map, width * height * bytes);
		if (len <=  0) {
			free (map);
			return (NULL);
		}
		*size = 0;
		if (palette == VIDEO_PALETTE_YUV420P) {
			convmap = malloc ( width * height * bytes );
			v4l_yuv420p2rgb (convmap, map, width, height, bytes * 8);
			memcpy (map, convmap, (size_t) width * height * bytes);
			free (convmap);
		} else if (palette == VIDEO_PALETTE_YUV422P) {
			convmap = malloc ( width * height * bytes );
			v4l_yuv422p2rgb (convmap, map, width, height, bytes * 8);
			memcpy (map, convmap, (size_t) width * height * bytes);
			free (convmap);
		}
		return (map);
	}

	map = mmap (0, vid_buf.size, PROT_READ|PROT_WRITE,MAP_SHARED,dev,0);
	if ((unsigned char *)-1 == (unsigned char *)map) {
		perror ("mmap()");
		return (NULL);
	}

	vid_mmap.format = palette;
	vid_mmap.frame = 0;
	vid_mmap.width = width;
	vid_mmap.height = height;
	if (ioctl (dev, VIDIOCMCAPTURE, &vid_mmap) == -1) {
		perror ("VIDIOCMCAPTURE");
		fprintf (stderr, "args: width=%d height=%d palette=%d\n",
					vid_mmap.width, vid_mmap.height, vid_mmap.format);
		munmap (map, vid_buf.size);
		return (NULL);
	}
	if (ioctl (dev, VIDIOCSYNC, &vid_mmap.frame) == -1) {
		perror ("VIDIOCSYNC");
		munmap (map, vid_buf.size);
		return (NULL);
	}
	*size = vid_buf.size;
	
	if (palette == VIDEO_PALETTE_YUV420P) {
		if (verbose)
			fprintf (stderr, "converting from YUV to RGB\n");
		convmap = malloc ( width * height * bytes );
		v4l_yuv420p2rgb (convmap, map, width, height, bytes * 8);
		memcpy (map, convmap, (size_t) width * height * bytes);
		free (convmap);
	} else if (palette == VIDEO_PALETTE_YUV422P) {
		if (verbose)
			fprintf (stderr, "converting from YUV to RGB\n");
		convmap = malloc ( width * height * bytes );
		v4l_yuv422p2rgb (convmap, map, width, height, bytes * 8);
		memcpy (map, convmap, (size_t) width * height * bytes);
		free (convmap);
	}
	
	return (map);
	if (verbose)
		fprintf (stderr, "got picture\n");
}

/*
 */
void
put_image_jpeg (FILE *out, char *image, int width, int height, int quality, int palette)
{
#ifdef HAVE_LIBJPEG
	int y, x, line_width;
	JSAMPROW row_ptr[1];
	struct jpeg_compress_struct cjpeg;
	struct jpeg_error_mgr jerr;
	char *line;

	line = malloc (width * 3);
	if (!line)
		return;
	if (verbose)
		fprintf (stderr, "writing JPEG data\n");
	cjpeg.err = jpeg_std_error(&jerr);
	jpeg_create_compress (&cjpeg);
	cjpeg.image_width = width;
	cjpeg.image_height= height;
	if (palette == VIDEO_PALETTE_GREY) {
		cjpeg.input_components = 1;
		cjpeg.in_color_space = JCS_GRAYSCALE;
	//	jpeg_set_colorspace (&cjpeg, JCS_GRAYSCALE);
	} else {
		cjpeg.input_components = 3;
		cjpeg.in_color_space = JCS_RGB;
	}
	jpeg_set_defaults (&cjpeg);
	jpeg_set_quality (&cjpeg, quality, TRUE);
	cjpeg.dct_method = JDCT_FASTEST;
	jpeg_stdio_dest (&cjpeg, out);


	jpeg_start_compress (&cjpeg, TRUE);
	row_ptr[0] = line;
	if (palette == VIDEO_PALETTE_GREY) {
		line_width = width;
		for ( y = 0; y < height; y++) {
			row_ptr[0] = image;
			jpeg_write_scanlines (&cjpeg, row_ptr, 1);
			image += line_width;
		}
	} else {
		line_width = width * 3;
		for ( y = 0; y < height; y++) {
			for (x = 0; x < line_width; x+=3) {
				line[x]   = image[x+2];
				line[x+1] = image[x+1];
				line[x+2] = image[x];
			}
			jpeg_write_scanlines (&cjpeg, row_ptr, 1);
			image += line_width;
		}
	}
	jpeg_finish_compress (&cjpeg);
	jpeg_destroy_compress (&cjpeg);
	free (line);
#endif
}

/*
 * write png image to stdout
 */
void
put_image_png (FILE *out, char *image, int width, int height, int palette)
{
#ifdef HAVE_LIBPNG
	int y, bpp;
	char *p;
	png_infop info_ptr;
	png_structp png_ptr = png_create_write_struct (PNG_LIBPNG_VER_STRING,
						NULL, NULL, NULL);
	if (!png_ptr)
		return;
	info_ptr = png_create_info_struct (png_ptr);
	if (!info_ptr)
		return;

	png_init_io (png_ptr, out);
	if (palette == VIDEO_PALETTE_GREY) {
		png_set_IHDR (png_ptr, info_ptr, width, height,
					8, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE,
					PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
		bpp = 1;
	} else {
		png_set_IHDR (png_ptr, info_ptr, width, height,
					8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
					PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
		bpp = 3;
	}
	png_set_bgr (png_ptr);
	png_write_info (png_ptr, info_ptr);
	p = image;
	for (y = 0; y < height; y++) {
		png_write_row (png_ptr, p);
		p += width * bpp;
	}
	png_write_end (png_ptr, info_ptr);
#endif
}

/*
 * write ppm image to stdout / file
 */
void
put_image_ppm (FILE *out, char *image, int width, int height, int binary)
{
	int x, y, ls=0;
	unsigned char *p = (unsigned char *)image;
	if (!binary) {
		fprintf (out, "P3\n%d %d\n%d\n", width, height, 255);
		for (x = 0; x < width; x++) {
			for (y = 0; y < height; y++) {
				fprintf (out, "%03d %03d %03d  ", p[2], p[1], p[0]);
				p += 3;
				if (ls++ > 4) {
					fprintf (out, "\n");
					ls = 0;
				}
			}
		}
		fprintf (out, "\n");
	} else {
		unsigned char buff[3];
		fprintf (out, "P6\n%d %d\n%d\n", width, height, 255);
		for (x = 0; x < width * height; x++) {
			buff[0] = p[2];
			buff[1] = p[1];
			buff[2] = p[0];
			fwrite (buff, 1, 3, out);
			p += 3;
		}
	}
	fflush (out);
}

/*
 * write pgm image to stdout / file
 */
void
put_image_pgm (FILE *out, char *image, int width, int height, int binary)
{
	int x, y, ls=0;
	unsigned char *p = (unsigned char *)image;
	if (!binary) {
		fprintf (out, "P2\n%d %d\n%d\n", width, height, 255);
		for (x = 0; x < width; x++) {
			for (y = 0; y < height; y++) {
				fprintf (out, "%03d ", p[0]);
				p++;
				if (ls++ > 4) {
					fprintf (out, "\n");
					ls = 0;
				}
			}
		}
		fprintf (out, "\n");
	} else {
		fprintf (out, "P5\n%d %d\n%d\n", width, height, 255);
		for (x = 0; x < width * height; x++) {
			fwrite (p, 1, 1, out);
			p++;
		}
	}
	fflush (out);
}

/*
 * write YUV4MPEG stream which is nice for mpeg2enc
 */
int
to_yuv (FILE *out, int fd, int width, int height)
{
	struct video_mbuf vid_buf;
	struct video_mmap vid_mmap;
	int do_read = 0;
	int done = 0;
	char *map;
	int size;
	int num = 0;
	double ms_time0, ms_time1;
	int tpf = 40;	/* 40 ms time per frame (= 25 fps) */

	if (ioctl (fd, VIDIOCGMBUF, &vid_buf) == -1) {
		do_read = 1;
	} else {
		fprintf (stderr, "buffsize=%d frames=%d\n",vid_buf.size,vid_buf.frames);
	}

	if (!do_read) {
		map = mmap (0, vid_buf.size, PROT_READ|PROT_WRITE,MAP_SHARED, fd, 0);
		if ((unsigned char *)-1 == (unsigned char *)map) {
			perror ("mmap()");
			return -1;
		}
		vid_mmap.format = VIDEO_PALETTE_YUV420P;
		vid_mmap.frame = 0;
		vid_mmap.width = width;
		vid_mmap.height =height;
		size = (width * height) + (width * height / 2);

		fprintf (stderr, "%dx%d bufsize=%d size=%d\n",
				width, height, vid_buf.size, size);

		printf ("YUV4MPEG%d %d %d\n", width, height, 3);

		if (ioctl (fd, VIDIOCMCAPTURE, &vid_mmap) == -1) {
			perror ("ioctl VIDIOCMCAPTURE");
			munmap (map, vid_buf.size);
			return -1;
		}
		vid_mmap.frame = 1;
		if (ioctl (fd, VIDIOCMCAPTURE, &vid_mmap) == -1) {
			perror ("ioctl VIDIOCMCAPTURE");
			munmap (map, vid_buf.size);
			return -1;
		}
		while (!done) {
			ms_time0 = ms_time(); /* milli seconds */
			vid_mmap.frame = vid_mmap.frame > 0 ? 0 : 1;
			if (ioctl (fd, VIDIOCSYNC, &vid_mmap.frame) == -1) {
				perror ("ioctl VIDIOCSYNC");
				munmap (map, vid_buf.size);
				return -1;
			}
			printf ("FRAME\n");
			fwrite (map + vid_buf.offsets[vid_mmap.frame], 1, size, stdout);
			if (ioctl (fd, VIDIOCMCAPTURE, &vid_mmap) == -1) {
				perror ("ioctl VIDIOCMCAPTURE");
				munmap (map, vid_buf.size);
				return -1;
			}
			num++;
			ms_time1 = ms_time () - ms_time0;
			if (ms_time1 < (double)tpf) {
				usleep (tpf - (int)ms_time1);
			} else {
				fprintf (stderr, "delayed: dt=%f\n",ms_time1 - (double)tpf);
			}
		}
		munmap (map, vid_buf.size);
	} else {
		fprintf (stderr, "still not implemented\n");
	}
	return 0;
}

/*
 * main()
 */
int
main (int argc, char *argv[])
{
	int width = DEF_WIDTH, height = DEF_HEIGHT, size, dev = -1, c;
	char *image, *device = VIDEO_DEV, *file = NULL;
	int max_try = 5;	/* we try 5 seconds/times to open the device */
	int quality = QUAL_DEFAULT;	/* default jpeg quality setting */
	int input = INPUT_DEFAULT; /* this means take over current device settings*/
	int norm  = NORM_DEFAULT;
	int loop =0 ;
	int binary = 0;
	int palette = VIDEO_PALETTE_RGB24;
	//int palette = VIDEO_PALETTE_YUV420;
	int num = 0;
	FILE *out = stdout;
#ifdef HAVE_LIBJPEG
	int format = FMT_JPEG;
#else
#	ifdef HAVE_LIBPNG
	int format = FMT_PNG;
#	else
	int format = FMT_PPM;
#	endif
#endif

	while ((c = getopt (argc, argv, "bd:f:gi:ln:o:p:q:s:vV")) != EOF) {
		switch (c) {
			case 'b': /* PPM as binary file */
				binary = 1;
				break;
			case 'd': /* change default device */
				device = optarg;
				break;
			case 'f':
				if (strcasecmp ("yuv4mpeg", optarg) == 0)
					format = FMT_YUV4MPEG;
				else if (strcasecmp ("png", optarg) == 0)
					format = FMT_PNG;
				else if (strcasecmp ("ppm", optarg) == 0)
					format = FMT_PPM;
				else if (strcasecmp ("pgm", optarg) == 0) {
					format = FMT_PGM;
					palette = VIDEO_PALETTE_GREY;
				} else if (strcasecmp ("jpeg", optarg) == 0)
					format = FMT_JPEG;
				else
					format = FMT_UNKNOWN;
				break;
			case 'g':
				palette = VIDEO_PALETTE_GREY;
				break;
			case 'i':
				if (strcasecmp ("tv", optarg) == 0) {
					input = IN_TV;
				} else if (strcasecmp ("comp1", optarg) == 0) {
					input = IN_COMPOSITE;
				} else if (strcasecmp ("comp2", optarg) ==0) {
					input = IN_COMPOSITE2;
				} else if (strcasecmp ("s-video", optarg) == 0) {
					input = IN_SVIDEO;
				} else {
					usage (argv[0]);
				}
				break;
			case 'l':
				loop = 1;
				break;
			case 'n':
				if (strcasecmp ("pal", optarg) == 0)
					norm = NORM_PAL;
				else if (strcasecmp ("ntsc", optarg) == 0)
					norm = NORM_NTSC;
				else if (strcasecmp ("secam", optarg) == 0)
					norm = NORM_SECAM;
				else
					usage (argv[0]);
				break;
			case 'o':
				file = optarg;
				break;
			case 'p':
				switch (*optarg) {
					case 'R':
					case 'c':
						palette = VIDEO_PALETTE_RGB24;
						break;
					case 'y':
						palette = VIDEO_PALETTE_YUV420P;
						break;
					case 'Y':
						palette = VIDEO_PALETTE_YUV422P;
						break;
					case 'g':
						palette = VIDEO_PALETTE_GREY;
						break;
					default:
						usage (argv[0]);
						break;
				}
				break;
			case 'q':
				sscanf (optarg, "%d", &quality);
				break;
			case 's':
				sscanf (optarg, "%dx%d", &width, &height);
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				printf ("Vidcat, Version %s\n", VERSION);
				exit (0);
				break;
			default:
				usage (argv[0]);
				break;
		}
	}
	if (verbose) {
		fprintf (stderr, "input palette: %s\n",
			palette == VIDEO_PALETTE_GREY ? "grey" :
			palette == VIDEO_PALETTE_RGB24 ? "rgb" :
			palette == VIDEO_PALETTE_YUV420P ? "yuv420" : "yuv422");
		fprintf (stderr, "size: %dx%d\n", width, height);
	}
	if (file) {
		out = fopen (file, "wb");
		if (!out) {
			perror (file);
			return 1;
		}
	}
again:
	/* open the video4linux device */
	while (max_try) {
		dev = open (device, O_RDWR);
		if (dev == -1) {
			if (!--max_try) {
				fprintf (stderr, "Can't open device %s\n", device);
				return (1);
			}
			sleep (1);
		} else { break; }
	}
	if (!num) {
		/* if we loop we have to do this only once. so
		 * check frame number and execute only for the
		 * frame number "0".
		 */
		if (v4l_set_input (dev, input, norm) == -1) {
			return (1);
		}
		if (v4l_check_size (dev, &width, &height) == -1) {
			return (1);
		}
		/*if (v4l_check_palette (dev, &palette) == -1) {
			return (1);
		}*/
	}
	switch (format) {
		case FMT_YUV4MPEG:
			if (palette == VIDEO_PALETTE_YUV420P)
				return to_yuv (out, dev, width, height);
			break;
	}
	image = get_image (dev, width, height, palette, &size);
	if (!size)
		close (dev);
	if (image) {
		switch (format) {
			case FMT_PPM:
				if (palette == VIDEO_PALETTE_GREY)
					put_image_pgm (out, image, width, height, binary);
				else
					put_image_ppm (out, image, width, height, binary);
				break;
			case FMT_PGM:
				put_image_pgm (out, image, width, height, binary);
				break;
			case FMT_PNG:
				put_image_png (out, image, width, height, palette);
				break;
			case FMT_JPEG:
				put_image_jpeg (out, image, width, height, quality, palette);
				break;
			default:
				fprintf (stderr, "Unknown format (%d)\n", format);
				break;
		}
		if (size) {
			munmap (image, size);
			close (dev);
		} else if (image) {
			free (image);
		}
		if (loop) {
			num++;
			goto again;
		}
	} else {
		fprintf (stderr, "Error: Can't get image\n");
	}
	return (0);
}

