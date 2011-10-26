/*
 * w3cam.c
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
#include <signal.h>
#include <errno.h>
#ifdef USE_SYSLOG
#include <syslog.h>
#endif
#if defined __GLIBC__ && __GLIBC__ >= 2
#include <libgen.h>	/* basename */
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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
#ifdef HAVE_LIBTTF
#include <freetype.h>
#endif
#include "w3cam.h"
#include "cgi.h"
#include "v4l.h"

/*
 * some default values, change these to fit your needs
 * most of these could be changed at runtime with config file
 */
#define FMT_DEFAULT		FMT_JPEG	/* FMT_PPM, FMT_JPEG, FMT_PNG */
#define QUALITY_DEFAULT	65			/* JPEG default quality */

#define WIDTH_DEFAULT	240			/* default width and height of the image */
#define HEIGHT_DEFAULT	180

#define MODE_DEFAULT	MODE_PLAIN	/* MODE_GUI or MODE_PLAIN */
#define USEC_DEFAULT	20000		/* wait microseconds before capturing */
#define REFRESH_DEFAULT	OFF			/* don't use refreshing */
#define MIN_REFRESH		0.0			/* min refresh time, compile time option */
#define FREQLIST_DEFAULT "878;9076;9844;9460"	/* default frequenzies */
#define MAX_TRY_OPEN	20			/* may be the device is locked, so try max*/
/* end of default values
 * *********************
 */


/*
 */
void
usage (char *pname, int width, int height, int color, int quality, int usec)
{
	cgi_response (http_bad_request, "text/html");
	printf (
	"<title>w3cam - help</title><pre>W3Cam, Version %s\n\n"
	"Usage: %s<?parameters>\n"
	"CGI parameters (GET or POST):\n"
	" help                                    show this page\n"
	" size=#x#                                geometry of picture "
		"[default = %dx%d]\n"
	" color={0|1}                             color or grey mode "
		"[default = %d]\n"
	" input={tv|composite|composite2|s-video} define input source\n"
	" quality={1-100}                         jpeg quality "
		"[default = %d]\n"
	" format={ppm|png|jpeg}                   output format\n"
	" freq=#                                  define frequenzy for TV\n"
	" usleep=#                                sleep # micro secs before cap. "
		"[default = %d]\n"
	" mode=[gui|html]                         build a page with panel or plain html\n"
	" refresh=#.#                             time in sec to refresh gui\n"
	" norm={pal|ntsc|secam}                   tv norm\n"
	" bgr={1|0}                               swap RGB to BGR (default: no)\n",
	VERSION, basename(pname), width, height, color, quality, usec);
	printf (
	"\nCompiled in features:\n");
#ifdef HAVE_LIBPNG
	printf (" PNG file format\n");
#endif
#ifdef HAVE_LIBJPEG
	printf (" JPEG file format\n");
#endif
#ifdef HAVE_LIBTTF
	printf ( " TTF/TimeStamp\n");
#endif
#ifdef USE_SYSLOG
	printf ( " SYSLOG support\n");
#endif
	exit (0);
}

/*
 */
void
log (char *info)
{
#ifdef USE_SYSLOG
	syslog (LOG_USER, "%s\n", info);
#else
	fprintf (stderr, "%s\n", info);
#endif
}

/*
 */
void
log2 (char *s1, char *s2)
{
#ifdef USE_SYSLOG
	syslog (LOG_USER, "%s %s\n", s1, s2);
#else
	fprintf (stderr, "%s %s\n", s1, s2);
#endif
}

/*
 * parse comma seperated frequency list
 */
char **
parse_list (char *freqs)
{
	char **flist = NULL;
	char *p = freqs, *end = NULL;
	int num = 0, i, len;

	if (!freqs)
		return (NULL);
	while ((p = strchr(p, ';')) != NULL) {
		p++;
		num++;
	}
	num++;
	flist = malloc ((num + 1) * sizeof (char *));
	flist[num] = NULL;
	p = freqs;
	for (i = 0; i < num; i++) {
		if (i == (num-1)) {
			/* last element */
			len = strlen (p);
		} else {
			end = strchr(p, ';');
			len = end - p;
		}
		flist[i] = malloc (len+1);
		strncpy (flist[i], p, len);
		p = end+1;
	}
	return (flist);
}

/*
 * read rgb image from v4l device
 * return: new allocated buffer
 */
unsigned char *
get_image (int dev, int width, int height, int input, int usec,
			unsigned long freq, int palette)
{
	struct video_mbuf vid_buf;
	struct video_mmap vid_mmap;
	char *map;
	unsigned char *buff;
	int size, len, bpp;
	register int i;

	if (input == IN_TV) {
		if (freq > 0) {
			if (ioctl (dev, VIDIOCSFREQ, &freq) == -1)
				log2 ("ioctl (VIDIOCSREQ):", strerror(errno));
		}
	}

	/* it seems some cards need a little bit time to come in
		sync with the new settings */
	if (usec)
		usleep (usec);

	if (palette != VIDEO_PALETTE_GREY) {
		/* RGB or YUV */
		size = width * height * 3;
		bpp = 3;
	} else {
		size = width * height * 1;
		bpp = 1;
	}
	vid_mmap.format = palette;

	if (ioctl (dev, VIDIOCGMBUF, &vid_buf) == -1) {
		/* do a normal read()
		 */
		struct video_window vid_win;

		if (ioctl (dev, VIDIOCGWIN, &vid_win) != -1) {
			vid_win.width  = width;
			vid_win.height = height;
			if (ioctl (dev, VIDIOCSWIN, &vid_win) == -1) {
				log2 ("ioctl(VIDIOCSWIN):", strerror(errno));
				return (NULL);
			}
		}
		map = malloc (size);
		if (!map)
			return (NULL);
		
		len = read (dev, map, size);
		if (len <= 0) {
			free (map);
			return NULL;
		}
		if (palette == VIDEO_PALETTE_YUV420P) {
			char *convmap;
            convmap = malloc ( width * height * bpp );
            v4l_yuv420p2rgb (convmap, map, width, height, bpp * 8);
            memcpy (map, convmap, (size_t) width * height * bpp);
            free (convmap);
        } else if (palette == VIDEO_PALETTE_YUV422P) {
			char *convmap;
            convmap = malloc ( width * height * bpp );
            v4l_yuv422p2rgb (convmap, map, width, height, bpp * 8);
            memcpy (map, convmap, (size_t) width * height * bpp);
            free (convmap);
		}
		return (map);
	}

	map = mmap (0, vid_buf.size, PROT_READ|PROT_WRITE,MAP_SHARED,dev,0);
	if ((unsigned char *)-1 == (unsigned char *)map) {
		log2 ("mmap():", strerror(errno));
		return (NULL);
	}
	vid_mmap.frame = 0;
	vid_mmap.width = width;
	vid_mmap.height =height;
	if (ioctl (dev, VIDIOCMCAPTURE, &vid_mmap) == -1) {
		log2 ("ioctl(VIDIOCMCAPTURE):", strerror(errno));
		munmap (map, vid_buf.size);
		return (NULL);
	}
	if (ioctl (dev, VIDIOCSYNC, &vid_mmap.frame) == -1) {
		log2 ("ioctl(VIDIOCSYNC):", strerror(errno));
		munmap (map, vid_buf.size);
		return (NULL);
	}
	buff = (unsigned char *) malloc (size);
	if (buff) {
		if (palette == VIDEO_PALETTE_YUV420P) {
			v4l_yuv420p2rgb (buff, map, width, height, 24);
        } else if (palette == VIDEO_PALETTE_YUV422P) {
            v4l_yuv422p2rgb (buff, map, width, height, 24);
		} else {
			for (i = 0; i < size; i++)
				buff[i] = map[i];
		}
	} else {
		perror ("malloc()");
	}
	munmap (map, vid_buf.size);
	return (buff);
}

/*
 */
void
put_image_jpeg (char *image, int width, int height, int quality, int color)
{
#ifdef HAVE_LIBJPEG
	register int x, y, line_width;
	JSAMPROW row_ptr[1];
	struct jpeg_compress_struct cjpeg;
	struct jpeg_error_mgr jerr;
	char *line = NULL;

	if (color) {
		line_width = width * 3;
		line = malloc (line_width);
		if (!line)
			return;
	} else {
		line_width = width;
	}
	cjpeg.err = jpeg_std_error(&jerr);
	jpeg_create_compress (&cjpeg);
	cjpeg.image_width = width;
	cjpeg.image_height= height;
	if (color) {
		cjpeg.input_components = 3;
		cjpeg.in_color_space = JCS_RGB;
	} else {
		cjpeg.input_components = 1;
		cjpeg.in_color_space = JCS_GRAYSCALE;
	}
	jpeg_set_defaults (&cjpeg);

	jpeg_simple_progression (&cjpeg);
	jpeg_set_quality (&cjpeg, quality, TRUE);
	cjpeg.dct_method = JDCT_FASTEST;
	jpeg_stdio_dest (&cjpeg, stdout);

	jpeg_start_compress (&cjpeg, TRUE);

	if (color) {
		row_ptr[0] = line;
		for ( y = 0; y < height; y++) {
			for (x = 0; x < line_width; x += 3) {
				line[x]   = image[x+2];
				line[x+1] = image[x+1];
				line[x+2] = image[x];
			}
			image += line_width;
			jpeg_write_scanlines (&cjpeg, row_ptr, 1);
		}
		free (line);
	} else {
		for ( y = 0; y < height; y++) {
			row_ptr[0] = image;
			jpeg_write_scanlines (&cjpeg, row_ptr, 1);
			image += line_width;
		}
	}
	jpeg_finish_compress (&cjpeg);
	jpeg_destroy_compress (&cjpeg);
#endif
}

/*
 * write png image to stdout
 */
void
put_image_png (char *image, int width, int height, int color)
{
#ifdef HAVE_LIBPNG
	register int y;
	register char *p;
	png_infop info_ptr;
	png_structp png_ptr = png_create_write_struct (PNG_LIBPNG_VER_STRING,
						NULL, NULL, NULL);
	if (!png_ptr)
		return;
	info_ptr = png_create_info_struct (png_ptr);
	if (!info_ptr)
		return;

	png_init_io (png_ptr, stdout);
	if (color) {
		png_set_IHDR (png_ptr, info_ptr, width, height,
					8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
					PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
		png_set_bgr (png_ptr);
	} else {
		png_set_IHDR (png_ptr, info_ptr, width, height,
					8, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE,
					PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
	}
	png_write_info (png_ptr, info_ptr);
	p = image;
	if (color) {
		width *= 3;
		for (y = 0; y < height; y++) {
			png_write_row (png_ptr, p);
			p += width;
		}
	} else {
		for (y = 0; y < height; y++) {
			png_write_row (png_ptr, p);
			p += width;
		}
	}
	png_write_end (png_ptr, info_ptr);
	png_destroy_write_struct (&png_ptr, &info_ptr);
#endif
}

/*
 * write ppm image to stdout
 */
void
put_image_ppm (char *image, int width, int height)
{
	int x, y, ls=0;
	unsigned char *p = (unsigned char *)image;
	printf ("P3\n%d %d\n%d\n", width, height, 255);
	for (x = 0; x < width; x++) {
		for (y = 0; y < height; y++) {
			printf ("%03d %03d %03d  ", p[2], p[1], p[0]);
			p += 3;
			if (ls++ > 4) {
				printf ("\n");
				ls = 0;
			}
		}
	}
}

/*
 */
const char *
palette2string (int palette) {
	if (palette == VIDEO_PALETTE_RGB24)
		return "rgb24";
	if (palette == VIDEO_PALETTE_YUV420P)
		return "yuv420p";
	if (palette == VIDEO_PALETTE_YUV422P)
		return "yuv422p";
	if (palette == VIDEO_PALETTE_GREY)
		return "grey";
	return "color";
}

/*
 * create a plain html page
 */
void
make_html (int width, int height, int color, int input, int fmt, int quality,
			float refresh, int us, int norm, int freq, char **freqs, int pal,
			int swapRGB)
{
	cgi_response (http_ok, "text/html");
	/* cgi_refresh (refresh, NULL); */
	cgi_html_start ("W3Cam");
	printf ("<DIV class=image><IMG width=%d height=%d src=\"%s?"
		"size=%dx%d&color=%s&id=%d&refresh=%1.2f&usleep=%d&freq=%d"
		"&mode=plain",
		width, height,
		cgi_script_name(),
		width, height, palette2string(pal),(int)time(NULL), refresh, us, freq);
	if (input != INPUT_DEFAULT)
		printf ("&input=%s", input == IN_TV? "tv" :
					input == IN_COMP1 ? "composite" :
					input == IN_COMP2? "composite2" : "s-video");
	if (norm != OFF)
		printf ("&norm=%s", norm == NORM_PAL ? "pal":
					norm == NORM_NTSC ? "ntsc" : "secam");
	if (fmt != FMT_DEFAULT)
		printf ("&format=%s", fmt == FMT_PNG? "png":
					fmt == FMT_JPEG? "jpeg": "ppm");
	if (quality)
		printf ("&quality=%d", quality);
	if (swapRGB)
		printf ("&bgr=1");
	printf ("\"></DIV>\n");
}


/*
 * create a html page with panel
 */
void
make_gui (int width, int height, int color, int input, int fmt, int quality,
			float refresh, int us, int norm, int freq, char **freqs, int pal,
			int swapRGB)
{
	make_html (width, height, color, input, fmt, quality,
			refresh, us, norm, freq, freqs, pal, swapRGB);

	printf ("<P><DIV class=panel><FORM>\n");
	printf ("<INPUT type=hidden name=width value=%d>", width);
	printf ("<INPUT type=hidden name=height value=%d>\n", height);
	printf ("<INPUT type=hidden name=mode value=gui>");
	printf ("<INPUT type=hidden name=quality value=%d>\n", quality);
	printf ("<INPUT type=hidden name=usleep value=%d>\n", us);

	printf ("Input:<SELECT name=input>\n");
	printf ("<option%s value='-1'>Default</option>",
				input == INPUT_DEFAULT? " selected":"");
	printf ("<option%s>TV</option>",
				input == IN_TV? " selected":"");
	printf ("<option%s>Composite</option>",
				input == IN_COMP1 ? " selected":"");
	printf ("<option%s>Composite2</option>",
				input == IN_COMP2? " selected":"");
	printf ("<option%s>S-Video</option></SELECT>\n",
				input == IN_SVIDEO? " selected":"");

	if ((norm != OFF) && (input == IN_TV)) {
		printf ("Norm:<SELECT name=norm>\n");
		printf ("<option%s>PAL</option>",   norm == NORM_PAL ? " selected":"");
		printf ("<option%s>NTSC</option>",  norm == NORM_NTSC? " selected":"");
		printf ("<option%s>SECAM</option>", norm == NORM_SECAM?" selected":"");
		printf ("<option>off</option>");	/* hide gui entry */
		printf ("</SELECT>\n");
	}
	if (freqs && (input == IN_TV)) {
		int f;
		printf ("Freq:<SELECT name=freq>\n");
		printf ("<option value=0>default</option>\n");
		while (*freqs) {
			f = atoi(*freqs);
			printf ("<option%s>%d</option>",  freq == f ? " selected": "", f);
			freqs++;
		}
		printf ("</SELECT>\n");
	}

	printf ("Format:<SELECT name=format>\n");
	printf ("<option%s>PPM", fmt == FMT_PPM? " selected":"");
	printf ("<option%s>PNG", fmt == FMT_PNG? " selected":"");
	printf ("<option%s>JPEG</SELECT>\n", fmt == FMT_JPEG? " selected":"");

	printf ("Size:<SELECT name=size>\n");
	printf ("<option%s>80x60\n", width == 80  ? " selected": "");
	printf ("<option%s>160x120", width == 160 ? " selected": "");
	printf ("<option%s>240x180", width == 240 ? " selected": "");
	printf ("<option%s>320x240", width == 320 ? " selected": "");
	printf ("<option%s>400x300", width == 400 ? " selected": "");
	printf ("<option%s>480x360", width == 480 ? " selected": "");
	printf ("<option%s>640x480", width == 640 ? " selected": "");
	printf ("<option%s>720x540", width == 720 ? " selected": "");
	printf ("<option%s>768x576</SELECT>\n", width == 768 ? " selected": "");

	printf ("Refresh (sec.):<SELECT name=refresh>\n");
	printf ("<OPTION value=\"-1\">off\n");
	printf ("<OPTION>0.0<OPTION>0.1<OPTION>0.5<OPTION>1.0<OPTION>2.0\n");
	printf ("<OPTION>3.0<OPTION>4.0<OPTION>5.0\n");
	printf ("<OPTION>10<OPTION>20<OPTION>40<OPTION>80\n");
	if (refresh != OFF)
		printf ("<option selected>%1.2f</SELECT>\n", refresh);
	else
		printf ("</SELECT>\n");

	printf ("<P><input type=submit value=Update></FORM></DIV><P>\n");
	cgi_html_end ("<HR><DIV class=footer>w3cam, &copy; rasca</DIV>");
}

/*
 */
void
on_signal (int signum)
{
	exit (0);
}


#ifdef HAVE_LIBTTF
#include "font.c"
#endif

/*
 * main()
 */
int
main (int argc, char *argv[])
{
	int width = WIDTH_DEFAULT, height = HEIGHT_DEFAULT, dev = -1;
	char *val = NULL, **form = NULL, *image;
	char *boundary = "--w3cam-ns-boundary--may-not-work-with-ie--";
	char *freqlist = FREQLIST_DEFAULT;
	char **freqs = NULL;
	char *device = VIDEO_DEV;
	int max_try = MAX_TRY_OPEN;	/* we try 20 times (5 sec) to open the device */
	int quality = QUALITY_DEFAULT;	/* default jpeg quality setting */
	int input = INPUT_DEFAULT;
	int norm  = NORM_DEFAULT;
	int mode = MODE_DEFAULT;
	int color = TRUE;
	int swapRGB = FALSE;
	int palette = VIDEO_PALETTE_RGB24;
	float refresh = REFRESH_DEFAULT;
	float min_refresh = MIN_REFRESH;
	int format = FMT_DEFAULT;
	int usec = USEC_DEFAULT;
	int freq = 0;
	int protected = 0;
	char *mime = NULL;
#ifdef HAVE_LIBTTF
	char *font = NULL;
	char *timestamp = NULL;
	int font_size = 12;
#define TS_MAX 128
	/* timestamp string */
	char ts_buff[TS_MAX+1];
	int ts_len;
	int border = 2;
	int blend = 60;
	int align = 1;
	time_t t;
	struct tm *tm;
	TT_Engine engine;
	TT_Face face;
	TT_Face_Properties properties;
	TT_Instance instance;
	TT_Glyph *glyphs = NULL;
	TT_Raster_Map bit;
	TT_Raster_Map sbit;
#endif

#ifdef USE_SYSLOG
	openlog (argv[0], LOG_PID, LOG_USER);
#endif
	cgi_init (argv[0]);
	if (signal (SIGTERM, on_signal) == SIG_ERR) {
		log ("couldn't register handler for SIGTERM");
	}
	if (signal (SIGPIPE, on_signal) == SIG_ERR) {
		log ("couldn't register handler for SIGPIPE");
	}
	/* check some values from the config file
	 */
	val = cgi_cfg_value ("width");
	if (val) width = atoi (val);
	val = cgi_cfg_value ("height");
	if (val) height = atoi (val);
	val = cgi_cfg_value ("color");
	if (val) {
		if (strcasecmp (val, "yuv420p") == 0) {
			color = 1;
			palette = VIDEO_PALETTE_YUV420P;
		} else if (strcasecmp (val, "yuv422p") == 0) {
			color = 1;
			palette = VIDEO_PALETTE_YUV422P;
		} else if (*val == '0' || *val == 'g') {
			color = 0;
			palette = VIDEO_PALETTE_GREY;
		} else {
			color = 1;
		}
	}
	val = cgi_cfg_value ("refresh");
	if (val) refresh = atof (val);
	val = cgi_cfg_value ("norm");
	if (val) norm = atoi (val);
	val = cgi_cfg_value ("input");
	if (val) input = atoi (val);
	val = cgi_cfg_value ("format");
	if (val) format = atoi (val);
	val = cgi_cfg_value ("quality");
	if (val) quality = atoi (val);
	val = cgi_cfg_value ("mode");
	if (val) mode = atoi (val);
	val = cgi_cfg_value ("usleep");
	if (val) usec = atoi (val);
	val = cgi_cfg_value ("freq");
	if (val) freq = atoi (val);
	val = cgi_cfg_value ("freqlist");
	if (val) freqlist = val;
	val = cgi_cfg_value ("protected");
	if (val) protected = atoi (val);
	val = cgi_cfg_value ("device");
	if (val) device = val;
	val = cgi_cfg_value ("bgr");
	if (val) swapRGB = atoi (val);
#ifdef HAVE_LIBTTF
	val = cgi_cfg_value ("font");
	if (val) font = val;
	val = cgi_cfg_value ("font_size");
	if (val) font_size = atoi (val);
	val = cgi_cfg_value ("timestamp");
	if (val) timestamp = val;
	val = cgi_cfg_value ("timestamp_border");
	if (val) border = atoi (val);
	val = cgi_cfg_value ("timestamp_blend");
	if (val) blend = atoi (val);
	val = cgi_cfg_value ("timestamp_align");
	if (val) align = atoi (val);
#endif

	/* parse the form, if there is any
	 */
	if (!protected)
		form = cgi_parse_form ();

	if (form && !protected) {
		val = cgi_form_value ("help");
		if (val) {
			usage (argv[0], width, height, color, quality, usec);
		}
		val = cgi_form_value ("size");
		if (val) {
			sscanf (val, "%dx%d", &width, &height);
		}
		val = cgi_form_value ("color");
		if (val) {
			if (strcasecmp (val, "yuv420p") == 0) {
				color = 1;
				palette = VIDEO_PALETTE_YUV420P;
			} else if (strcasecmp (val, "yuv422p") == 0) {
				color = 1;
				palette = VIDEO_PALETTE_YUV422P;
			} else if (*val == '0' || *val == 'g') {
				color = 0;
				palette = VIDEO_PALETTE_GREY;
			} else {
				color = 1;
				palette = VIDEO_PALETTE_RGB24;
			}
		}
		val = cgi_form_value ("format");
		if (val) {
			if ((strcasecmp ("ppm", val) == 0) && color) {
				format = FMT_PPM;
			} else if (strcasecmp ("png", val) == 0) {
				format = FMT_PNG;
			} else if (strcasecmp ("jpeg", val) == 0) {
				format = FMT_JPEG;
			}
		}
		val = cgi_form_value ("refresh");
		if (val) refresh = atof (val);
		val = cgi_form_value ("quality");
		if (val) quality = atoi (val);
		val = cgi_form_value ("usleep");
		if (val) usec = atoi (val);
		val = cgi_form_value ("freq");
		if (val) freq = atoi (val);

		val = cgi_form_value ("mode");
		if (val) {
			if (strcmp ("gui", val) == 0)
				mode = MODE_GUI;
			else if (strcmp ("html", val) == 0)
				mode = MODE_HTML;
			else
				mode = MODE_PLAIN;
		}
		val = cgi_form_value ("input");
		if (val) {
			if (strcasecmp ("tv", val) == 0) {
				input = IN_TV;
			} else if (strcasecmp ("composite", val) == 0) {
				input = IN_COMP1;
			} else if (strcasecmp ("composite2", val) ==0) {
				input = IN_COMP2;
			} else if (strcasecmp ("s-video", val) == 0) {
				input = IN_SVIDEO;
			} else {
				input = INPUT_DEFAULT;
			}
		}
		val = cgi_form_value ("norm");
		if (val) {
			if (strcasecmp ("pal", val) == 0) {
				norm = NORM_PAL;
			} else if (strcasecmp ("ntsc", val) == 0) {
				norm = NORM_NTSC;
			} else if (strcasecmp ("secam", val) == 0) {
				norm = NORM_SECAM;
			} else {
				norm = OFF;
			}
		}
		val = cgi_form_value ("bgr");
		if (val) {
			/* check for yes,true,1 */
			if ((*val == '1') || (*val == 't') || (*val == 'y')) {
				swapRGB = 1;
			} else {
				swapRGB = 0;
			}
		}
	}

	if ((refresh > OFF) && (refresh < min_refresh))
		refresh = min_refresh;
	if (!*freqlist)
		freqlist = NULL;

	if (mode == MODE_GUI) {
		freqs = parse_list (freqlist);
		make_gui (width, height, color, input, format, quality, refresh, usec,
					norm,freq, freqs, palette, swapRGB);
		return (0);
	}
	if (mode == MODE_HTML) {
		freqs = parse_list (freqlist);
		make_html (width, height, color, input, format, quality, refresh, usec,
					norm,freq, freqs, palette, swapRGB);
		return (0);
	}
	switch (format) {
		case FMT_PPM:
			mime = "image/ppm";
			break;
		case FMT_JPEG:
			mime = "image/jpeg";
			break;
		case FMT_PNG:
			mime = "image/png";
			break;
		default:
			log ("unknown image format..!?");
			break;
	}
#ifdef HAVE_LIBTTF
	if (font && timestamp) {
		if (TT_Init_FreeType (&engine)) {
			font = NULL;
			goto no_time_stamp;
		}
		if (Face_Open (font, engine, &face, &properties, &instance, font_size)){
			TT_Done_FreeType (engine);
			font = NULL;
			goto no_time_stamp;
		}
	}
no_time_stamp:
#endif
	if (!color) {
		palette = VIDEO_PALETTE_GREY;
	}
	/* open the video4linux device */
again:
	while (max_try) {
		dev = open (device, O_RDWR);
		if (dev == -1) {
			log2 (device, strerror(errno));
			if (!--max_try) {
				cgi_response (http_ok, "text/plain");
				printf ("Can't open device %s: %s\n",device,strerror(errno));
				exit (0);
			}
			/* sleep 1/4 second */
			usleep (250000);
		} else {
			max_try = MAX_TRY_OPEN;	/* we may need it in a loop later .. */
			break;
		}
	}
	if (v4l_mute_sound (dev) == -1) {
		perror ("mute sound");
	}
	if (v4l_set_input (dev, input, norm) == -1) {
		return 1;
	}
	if (v4l_check_size (dev, &width, &height) == -1) {
		return 1;
	}
	/* if (v4l_check_palette (dev, &palette) == -1) {
		return 1;
	} */
again_without_open:
	image = get_image (dev, width, height, input, usec,freq, palette);
	if (image) {
		if (swapRGB && (palette == VIDEO_PALETTE_RGB24)) {
			int x,y;
			unsigned char *p, pt;
			p = image;
			for (y = 0; y < height; y++) {
				for (x = 0; x < width; x++) {
					pt = *p;
					*p = *(p+2);
					*(p+2) = pt;
					p += 3;
				}
			}
		}
		if (refresh != 0.0) {
			close (dev);
		}
		if (refresh != OFF) {
			cgi_multipart (boundary);
			printf ("Content-Type: %s\n\n", mime);
		} else {
			cgi_response (http_ok, mime);
		}
#ifdef HAVE_LIBTTF
	if (font && timestamp) {
		time (&t);
		tm = localtime (&t);
		ts_buff[TS_MAX] = '\0';
		strftime (ts_buff, TS_MAX, timestamp, tm);
		ts_len = strlen (ts_buff);

		glyphs = Glyphs_Load (face, &properties, instance, ts_buff, ts_len);
		Raster_Init(face, &properties,instance,ts_buff,ts_len, border, glyphs, &bit);
		Raster_Small_Init (&sbit, &instance);
		Render_String (glyphs, ts_buff, ts_len, &bit, &sbit, border);
		if (bit.bitmap) {
			int x, y, psize, i, x_off, y_off;
			unsigned char *p;

			if (color)
				psize = 3;
			else
				psize = 1;

			switch (align) {
				case 1:
					x_off = (width - bit.width) * psize;
					y_off = 0;
					break;
				case 2:
					x_off = 0;
					y_off = height - bit.rows;
					break;
				case 3:
					x_off = (width - bit.width) * psize;
					y_off = height - bit.rows;
					break;
				default:
					x_off = y_off = 0;
					break;
			}

			for (y = 0; y < bit.rows; y++) {
				p = image + (y + y_off) * (width * psize) + x_off;
				for (x = 0; x < bit.width; x++) {
					switch (((unsigned char *)bit.bitmap)
								[((bit.rows-y-1)*bit.cols)+x]) {
						case 0:
							for (i = 0; i < psize; i++) {
								*p = (255 * blend + *p * (100 - blend))/100;
								p++;
							}
							break;
						case 1:
							for (i = 0; i < psize; i++) {
								*p = (220 * blend + *p * (100 - blend))/100;
								p++;
							}
							break;
						case 2:
							for (i = 0; i < psize; i++) {
								*p = (162 * blend + *p * (100 - blend))/100;
								p++;
							}
							break;
						case 3:
							for (i = 0; i < psize; i++) {
								*p = (64 * blend + *p * (100 - blend))/100;
								p++;
							}
							break;
						default:
							for (i = 0; i < psize; i++) {
								*p = (0 * blend + *p * (100 - blend))/100;
								p++;
							}
							break;
					}
				}
			}
		}
		Raster_Done (&sbit);
		Raster_Done (&bit);
		Glyphs_Done (glyphs);
		glyphs = NULL;
	}
#endif
		switch (format) {
			case FMT_PPM:
				put_image_ppm (image, width, height);
				printf ("\n%s\n", boundary);
				break;
			case FMT_PNG:
				put_image_png (image, width, height, color);
				printf ("\n%s\n", boundary);
				break;
			case FMT_JPEG:
				put_image_jpeg (image, width, height, quality, color);
				printf ("\n%s\n", boundary);
				break;
			default:
				/* should never be reached */
				printf ("Unknown format (%d)\n", format);
				printf ("\n%s\n", boundary);
				break;
		}
		free (image);
		if (refresh == 0.0) {
			fflush (stdout);
			/* wait ? */
			goto again_without_open;
		}
		if (refresh != OFF) {
			fflush (stdout);
			usleep ((int)(refresh * 1000000));
			goto again;
		}
	} else {
		cgi_response (http_ok, "text/plain");
		printf ("Error: Can't get image\n");
		close (dev);
	}
#ifdef HAVE_LIBTTF
	if (font && timestamp) {
		Face_Done (instance, face);
		TT_Done_FreeType (engine);
	}
#endif
	return (0);
}

