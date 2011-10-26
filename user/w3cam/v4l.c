/*
 * v4l.c
 *
 * Copyright (C) 2001 Rasca, Berlin
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
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/videodev.h>
#include "v4l.h"

#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

/*
 * set the input and norm for the video4linux device
 */
int
v4l_set_input (int fd, int input, int norm)
{
	struct video_channel vid_chnl;

	if (input != INPUT_DEFAULT || norm != NORM_DEFAULT) {
		if (vid_chnl.channel != INPUT_DEFAULT)
			vid_chnl.channel = input;
		else
			vid_chnl.channel = 0;
		vid_chnl.norm = -1;
		if (ioctl (fd, VIDIOCGCHAN, &vid_chnl) == -1) {
			perror ("ioctl (VIDIOCGCHAN)");
			return -1;
		} else {
			if (input != 0)
				vid_chnl.channel = input;
			if (norm != NORM_DEFAULT)
				vid_chnl.norm    = norm;
			if (ioctl (fd, VIDIOCSCHAN, &vid_chnl) == -1) {
				perror ("ioctl (VIDIOCSCHAN)");
				return -1;
			}
		}
	}
	return 0;
}

/*
 * check the size and readjust if necessary
 */
int
v4l_check_size (int fd, int *width, int *height)
{
	struct video_capability vid_caps;

	if (ioctl (fd, VIDIOCGCAP, &vid_caps) == -1) {
		perror ("ioctl (VIDIOCGCAP)");
		return -1;
	}
	/* readjust if necessary */
	if (*width > vid_caps.maxwidth || *width < vid_caps.minwidth) {
		*width = min (*width, vid_caps.maxwidth);
		*width = max (*width, vid_caps.minwidth);
		fprintf (stderr, "readjusting width to %d\n", *width);
	}
	if (*height > vid_caps.maxheight || *height < vid_caps.minheight) {
		*height = min (*height, vid_caps.maxheight);
		*height = max (*height, vid_caps.minheight);
		fprintf (stderr, "readjusting height to %d\n", *height);
	}
	return 0;
}

/*
 * check the requested palette and adjust if possible
 * seems not to work :-(
 */
int
v4l_check_palette (int fd, int *palette)
{
	struct video_picture vid_pic;

	if (!palette)
		return -1;

	if (ioctl (fd, VIDIOCGPICT, &vid_pic) == -1) {
		perror ("ioctl (VIDIOCGPICT)");
		return -1;
	}
	vid_pic.palette = *palette;
	if (ioctl (fd, VIDIOCSPICT, &vid_pic) == -1) {
		/* try YUV420P
		 */
		fprintf (stderr, "failed\n");
		vid_pic.palette = *palette = VIDEO_PALETTE_YUV420P;
		if (ioctl (fd, VIDIOCSPICT, &vid_pic) == -1) {
			perror ("ioctl (VIDIOCSPICT) to YUV");
			/* ok, try grayscale..
			 */
			vid_pic.palette = *palette = VIDEO_PALETTE_GREY;
			if (ioctl (fd, VIDIOCSPICT, &vid_pic) == -1) {
				perror ("ioctl (VIDIOCSPICT) to GREY");
				return -1;
			}
		}
	}
	return 0;
}

/*
 * check if driver supports mmap'ed buffer
 */
int
v4l_check_mmap (int fd, int *size)
{
	struct video_mbuf vid_buf;

	if (ioctl (fd, VIDIOCGMBUF, &vid_buf) == -1) {
		return -1;
	}
	if (size)
		*size = vid_buf.size;
	return 0;
}

/*
 * mute sound if available
 */
int
v4l_mute_sound (int fd)
{
	struct video_capability vid_caps;
	struct video_audio vid_aud;

	if (ioctl (fd, VIDIOCGCAP, &vid_caps) == -1) {
		perror ("ioctl (VIDIOCGCAP)");
		return -1;
	}
	if (vid_caps.audios > 0) {
		/* mute the sound */
		if (ioctl (fd, VIDIOCGAUDIO, &vid_aud) == -1) {
			return -1;
        } else {
            vid_aud.flags = VIDEO_AUDIO_MUTE;
            if (ioctl (fd, VIDIOCSAUDIO, &vid_aud) == -1)
				return -1;
        }
    }
	return 0;
}

/*
 * Turn a YUV4:2:0 block into an RGB block
 *
 * Video4Linux seems to use the blue, green, red channel
 * order convention-- rgb[0] is blue, rgb[1] is green, rgb[2] is red.
 *
 * Color space conversion coefficients taken from the excellent
 * http://www.inforamp.net/~poynton/ColorFAQ.html
 * In his terminology, this is a CCIR 601.1 YCbCr -> RGB.
 * Y values are given for all 4 pixels, but the U (Pb)
 * and V (Pr) are assumed constant over the 2x2 block.
 *
 * To avoid floating point arithmetic, the color conversion
 * coefficients are scaled into 16.16 fixed-point integers.
 * They were determined as follows:
 *
 *	double brightness = 1.0;  (0->black; 1->full scale) 
 *	double saturation = 1.0;  (0->greyscale; 1->full color)
 *	double fixScale = brightness * 256 * 256;
 *	int rvScale = (int)(1.402 * saturation * fixScale);
 *	int guScale = (int)(-0.344136 * saturation * fixScale);
 *	int gvScale = (int)(-0.714136 * saturation * fixScale);
 *	int buScale = (int)(1.772 * saturation * fixScale);
 *	int yScale = (int)(fixScale);	
 */

/* LIMIT: convert a 16.16 fixed-point value to a byte, with clipping. */
#define LIMIT(x) ((x)>0xffffff?0xff: ((x)<=0xffff?0:((x)>>16)))

/*
 */
static inline void
v4l_copy_420_block (int yTL, int yTR, int yBL, int yBR, int u, int v, 
	int rowPixels, unsigned char * rgb, int bits)
{
	const int rvScale = 91881;
	const int guScale = -22553;
	const int gvScale = -46801;
	const int buScale = 116129;
	const int yScale  = 65536;
	int r, g, b;

	g = guScale * u + gvScale * v;
	r = rvScale * v;
	b = buScale * u;

	yTL *= yScale; yTR *= yScale;
	yBL *= yScale; yBR *= yScale;

	if (bits == 24) {
		/* Write out top two pixels */
		rgb[0] = LIMIT(b+yTL); rgb[1] = LIMIT(g+yTL); rgb[2] = LIMIT(r+yTL);
		rgb[3] = LIMIT(b+yTR); rgb[4] = LIMIT(g+yTR); rgb[5] = LIMIT(r+yTR);

		/* Skip down to next line to write out bottom two pixels */
		rgb += 3 * rowPixels;
		rgb[0] = LIMIT(b+yBL); rgb[1] = LIMIT(g+yBL); rgb[2] = LIMIT(r+yBL);
		rgb[3] = LIMIT(b+yBR); rgb[4] = LIMIT(g+yBR); rgb[5] = LIMIT(r+yBR);
	} else if (bits == 16) {
		/* Write out top two pixels */
		rgb[0] = ((LIMIT(b+yTL) >> 3) & 0x1F) | ((LIMIT(g+yTL) << 3) & 0xE0);
		rgb[1] = ((LIMIT(g+yTL) >> 5) & 0x07) | (LIMIT(r+yTL) & 0xF8);

		rgb[2] = ((LIMIT(b+yTR) >> 3) & 0x1F) | ((LIMIT(g+yTR) << 3) & 0xE0);
		rgb[3] = ((LIMIT(g+yTR) >> 5) & 0x07) | (LIMIT(r+yTR) & 0xF8);

		/* Skip down to next line to write out bottom two pixels */
		rgb += 2 * rowPixels;

		rgb[0] = ((LIMIT(b+yBL) >> 3) & 0x1F) | ((LIMIT(g+yBL) << 3) & 0xE0);
		rgb[1] = ((LIMIT(g+yBL) >> 5) & 0x07) | (LIMIT(r+yBL) & 0xF8);

		rgb[2] = ((LIMIT(b+yBR) >> 3) & 0x1F) | ((LIMIT(g+yBR) << 3) & 0xE0);
		rgb[3] = ((LIMIT(g+yBR) >> 5) & 0x07) | (LIMIT(r+yBR) & 0xF8);
	}
}

/*
 */
static inline void
v4l_copy_422_block (int yTL, int yTR, int u, int v, 
	int rowPixels, unsigned char * rgb, int bits)
{
	const int rvScale = 91881;
	const int guScale = -22553;
	const int gvScale = -46801;
	const int buScale = 116129;
	const int yScale  = 65536;
	int r, g, b;

	g = guScale * u + gvScale * v;
	r = rvScale * v;
	b = buScale * u;

	yTL *= yScale; yTR *= yScale;

	if (bits == 24) {
		/* Write out top two pixels */
		rgb[0] = LIMIT(b+yTL); rgb[1] = LIMIT(g+yTL); rgb[2] = LIMIT(r+yTL);
		rgb[3] = LIMIT(b+yTR); rgb[4] = LIMIT(g+yTR); rgb[5] = LIMIT(r+yTR);

	} else if (bits == 16) {
		/* Write out top two pixels */
		rgb[0] = ((LIMIT(b+yTL) >> 3) & 0x1F) | ((LIMIT(g+yTL) << 3) & 0xE0);
		rgb[1] = ((LIMIT(g+yTL) >> 5) & 0x07) | (LIMIT(r+yTL) & 0xF8);

		rgb[2] = ((LIMIT(b+yTR) >> 3) & 0x1F) | ((LIMIT(g+yTR) << 3) & 0xE0);
		rgb[3] = ((LIMIT(g+yTR) >> 5) & 0x07) | (LIMIT(r+yTR) & 0xF8);
	}
}

/*
 * convert a YUV420P to a rgb image
 */
int
v4l_yuv420p2rgb (unsigned char *rgb_out, unsigned char *yuv_in,
		int width, int height, int bits)
{
	const int numpix = width * height;
	const unsigned int bytes = bits >> 3;
	int h, w, y00, y01, y10, y11, u, v;
	unsigned char *pY = yuv_in;
	unsigned char *pU = pY + numpix;
	unsigned char *pV = pU + numpix / 4;
	unsigned char *pOut = rgb_out;

	if (!rgb_out || !yuv_in)
		return -1;

	for (h = 0; h <= height - 2; h += 2) {
		for (w = 0; w <= width - 2; w += 2) {
			y00 = *(pY);
			y01 = *(pY + 1);
			y10 = *(pY + width);
			y11 = *(pY + width + 1);
			u = (*pU++) - 128;
			v = (*pV++) - 128;

			v4l_copy_420_block (y00, y01, y10, y11, u, v, width, pOut, bits);
	
			pY += 2;
			pOut += bytes << 1;

		}
		pY += width;
		pOut += width * bytes;
	}
	return 0;
}

/*
 * convert a YUV422P to a rgb image
 */
int
v4l_yuv422p2rgb (unsigned char *rgb_out, unsigned char *yuv_in,
		int width, int height, int bits)
{
	const int numpix = width * height;
	const unsigned int bytes = bits >> 3;
	int h, w, y00, y01, u, v;
	unsigned char *pY = yuv_in;
	unsigned char *pU = pY + numpix;
	unsigned char *pV = pU + numpix / 2;
	unsigned char *pOut = rgb_out;

	if (!rgb_out || !yuv_in)
		return -1;

	for (h = 0; h < height; h += 1) {
		for (w = 0; w <= width - 2; w += 2) {
			y00 = *(pY);
			y01 = *(pY + 1);
			u = (*pU++) - 128;
			v = (*pV++) - 128;

			v4l_copy_422_block (y00, y01, u, v, width, pOut, bits);
	
			pY += 2;
			pOut += bytes << 1;

		}
		//pY += width;
		//pOut += width * bytes;
	}
	return 0;
}
