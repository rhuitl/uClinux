/*
 *  user/de2ts-cal/de2ts-cal.c -- Touchscreen driver calibration
 *
 *	Copyright (C) 2003 Georges Menie
 *
 *  This is a DragonEngine board specific app.
 *
 *  Run it on this board, two targets will be displayed, use the touchscreen
 *  to hit the target centers then one more time to check the calibration.
 *  If the final target not clicked right, the calibration start over.
 *
 *  The calibration data can be stored into the eeprom (use the compilation
 *  option USE_EEPROM=1), it will be stored at the end of the eeprom.
 *  If you don't have or if you don't want to use the eeprom, then you may
 *  either run this prog before running your apps, or you can run it once
 *  and record the calibration data displayed on the tty then run
 *  de2ts-cal -f -- <cal data> before running your app.
 *  see usage() below
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <math.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/fb.h>
#include <linux/de2ts.h>
#include "screen.h"

#ifndef USE_EEPROM
#define USE_EEPROM 0
#endif

#define debug 0

#include "target.h"

#define TOUCHSCREEN_DEVICE "/dev/ts"
#define FRAMEBUFFER_DEVICE "/dev/fb0"

Bitmap screen;
static void error(int code, char *fmt, ...);
static void debugmsg(char *fmt, ...);

#if USE_EEPROM

#define EEPROM_DEVICE "/dev/eeprom"
#define EEPROM_CAL_MAGIC 0xbebe2003

static struct {
	int magic;
	struct de2ts_cal_params prm;
	unsigned short cksum;
} eep_stored_prm;

static int eepromWriteCalData(struct de2ts_cal_params *prm)
{
	int eep_fd, count;
	unsigned short cks;

	if (debug)
		debugmsg("eepromWriteCalData(...)\n");

	eep_stored_prm.magic = EEPROM_CAL_MAGIC;
	eep_stored_prm.cksum = 0;
	eep_stored_prm.prm = *prm;

	for (count = cks = 0; count < sizeof eep_stored_prm / 2; ++count) {
		cks += *(((unsigned short *) &eep_stored_prm) + count);
	}
	eep_stored_prm.cksum = -cks;

	eep_fd = open(EEPROM_DEVICE, O_RDWR);
	if (eep_fd < 0) {
		error(0, "Error opening eeprom");
		return -1;
	}

	/* calibration data are stored at the end of the eeprom */
	if (lseek(eep_fd, -sizeof eep_stored_prm, SEEK_END) < 0) {
		error(0, "Error seeking eeprom");
		close(eep_fd);
		return -1;
	}

	count = write(eep_fd, &eep_stored_prm, sizeof eep_stored_prm);
	if (count != sizeof eep_stored_prm) {
		error(0, "Error writing eeprom");
		close(eep_fd);
		return -1;
	}

	close(eep_fd);
	return 0;
}

static int eepromLoadContent(int fd)
{
	int eep_fd, count;
	unsigned short cks;

	if (debug)
		debugmsg("eepromLoadContent(...)\n");

	eep_fd = open(EEPROM_DEVICE, O_RDONLY);
	if (eep_fd < 0)
		return -1;

	/* calibration data are stored at the end of the eeprom */
	if (lseek(eep_fd, -sizeof eep_stored_prm, SEEK_END) < 0)
		return -1;

	count = read(eep_fd, &eep_stored_prm, sizeof eep_stored_prm);
	if (count != sizeof eep_stored_prm)
		return -1;

	close(eep_fd);

	if (eep_stored_prm.magic != EEPROM_CAL_MAGIC)
		return -1;

	for (count = cks = 0; count < sizeof eep_stored_prm / 2; ++count) {
		cks += *(((unsigned short *) &eep_stored_prm) + count);
	}

	if (cks)
		return -1;

	if (ioctl(fd, DE2TS_CAL_PARAMS_SET, &eep_stored_prm.prm) < 0)
		return -1;

	return 0;
}

#endif

static void xor_bitmap(unsigned char *srcptr, int w, int h, int x, int y)
{
	int l, c, src, dst;
	unsigned char byte;

	if (w & 3 || x & 3)
		error(EXIT_FAILURE, "Unsupported bitmap operation");

	for (l = 0; l < h; ++l) {
		for (c = 0; c < w / 8; ++c) {
			dst = ((y + l) * screen.line_length) + (x / 8) + c;
			src = (l * w / 8) + c;
			screen.ptr[dst] = screen.inverted ^
				((screen.inverted ^ screen.ptr[dst]) ^ srcptr[src]);
		}
	}
}

static void next_up_event(int fd, struct de2ts_event *ev)
{
	int r;

	while ((r = read(fd, ev, sizeof(struct de2ts_event))) ==
		   sizeof(struct de2ts_event)) {
		if (ev->event == EV_PEN_UP)
			return;
	}
	if (r >= 0)
		error(EXIT_FAILURE, "Touchscreen read interrupted");
	else
		error(EXIT_FAILURE, "Touchscreen read error");
}

static void calibration(int fd, struct de2ts_cal_params *prm)
{
	int x0, x1, y0, y1;
	double k, off, den;
	struct de2ts_event ev;

	if (debug)
		debugmsg("calibration(...)\n");

	while (1) {
		/* clear the screen */
		memset(screen.ptr, screen.inverted, screen.length);

		/* set the calibration to full range */
		prm->version = 0;
		if (ioctl(fd, DE2TS_CAL_PARAMS_SET, prm) < 0)
			error(EXIT_FAILURE, "Unable to set touchscreen information");

		/* display the first text */
		display_1();

		/* display the first target */
		xor_bitmap(target_bits, target_width, target_height, 0,
				   screen.height - target_height);

		/* read touchscreen */
		next_up_event(fd, &ev);
		x0 = ev.x;
		y0 = ev.y;

		/* hide the first target */
		xor_bitmap(target_bits, target_width, target_height, 0,
				   screen.height - target_height);
		/* display the second target */
		xor_bitmap(target_bits, target_width, target_height,
				   screen.width - target_width, 0);

		/* read touchscreen */
		next_up_event(fd, &ev);
		x1 = ev.x;
		y1 = ev.y;

		/* hide the second target */
		xor_bitmap(target_bits, target_width, target_height,
				   screen.width - target_width, 0);

		/* compute the new calibration data */
		k = ((double)screen.width - target_width/2)/(target_width/2);
		prm->version = DE2TS_VERSION;
		off = (x1-(k*x0))/(1-k);
		den = (x0-off)*screen.width/(target_width/2);
		prm->xoff = floor(off);
		prm->xden = floor(den);
		off = (y0-(k*y1))/(1-k);
		den = (y1-off)*screen.width/(target_width/2);
		prm->yoff = floor(off);
		prm->yden = floor(den);
		prm->xrng = screen.width;
		prm->yrng = screen.height;

		if (prm->xden == 0 || prm->yden == 0)
			continue;

		/* setup the touchscreen driver */
		if (ioctl(fd, DE2TS_CAL_PARAMS_SET, prm) < 0)
			error(EXIT_FAILURE, "Unable to set touchscreen information");

		/* display the second text */
		display_2();

		/*
		 * check calibration
		 */

		x0 = screen.width * 2 / 3;
		x0 &= ~0x03;			/* align to a byte boundary */
		y0 = screen.height * 2 / 3;

		/* display the last target */
		xor_bitmap(target_bits, target_width, target_height, x0, y0);

		/* read touchscreen */
		next_up_event(fd, &ev);

		if (ev.x >= x0 + target_width/2 - 6 && ev.x <= x0 + target_width/2 + 6) {
			if (ev.y >= y0 + target_height/2 - 6 && ev.y <= y0 + target_height/2 + 6) {
				break;
			}
		}
	}

	/* clear the screen */
	memset(screen.ptr, screen.inverted, screen.length);

	printf("Touchscreen new calibration data: %d %d %d %d %d %d\n",
		   prm->xoff, prm->xden, prm->yoff, prm->yden, prm->xrng,
		   prm->yrng);
}

static void init_screen(int inv)
{
	struct fb_fix_screeninfo fscreeninfo;
	struct fb_var_screeninfo screeninfo;
	int fd;

	if (debug)
		debugmsg("init_screen(%d)\n", inv);

	if ((fd = open(FRAMEBUFFER_DEVICE, O_RDWR)) < 0)
		error(EXIT_FAILURE, "Unable to open framebuffer device");

	if (ioctl(fd, FBIOGET_FSCREENINFO, &fscreeninfo) < 0)
		error(EXIT_FAILURE, "Unable to retrieve framebuffer information");

	if (ioctl(fd, FBIOGET_VSCREENINFO, &screeninfo) < 0)
		error(EXIT_FAILURE, "Unable to retrieve framebuffer information");

	screen.width = screeninfo.xres_virtual;
	screen.height = screeninfo.yres_virtual;
	screen.inverted = (inv || (fscreeninfo.visual == FB_VISUAL_MONO01)) ?
		-1 : 0;
	screen.length = fscreeninfo.smem_len;
	screen.line_length = fscreeninfo.line_length;

	if (debug)
		debugmsg("init_screen: %dx%d (line: %dB screen: %dB)\n",
			screen.width, screen.height, screen.line_length, screen.length);

	if ((screen.ptr =
		 mmap(0, screen.length, PROT_READ | PROT_WRITE,
			  0, fd, 0)) == MAP_FAILED)
		error(EXIT_FAILURE, "Unable to mmap framebuffer");

	if (screen.ptr == NULL)
		error(EXIT_FAILURE, "Framebuffer address error");

	if (debug)
		debugmsg("init_screen: screen.ptr=0x%08x\n", screen.ptr);
}

static int usage(char *prog)
{
	printf("\nUsage: %s [options] [-- xoff xden yoff yden xrng yrng]\n",
		   prog);
	printf("options:\n");
	printf("  -h this help message\n");
	printf("  -i invert display\n");
	printf("  -f use fixed calibration data "
		   "(6 integers at the end of the command line)\n");
	printf("  -w write calibration data to eeprom (%s)\n",
#if USE_EEPROM
		   EEPROM_DEVICE);
#else
		   "not available");
#endif
	printf("  -c verify eeprom and set calibration data\n");
	printf("\nExample:\n");
	printf("\ninteractive calibration "
		   "(display the resulting calibration values):\n");
	printf("  %s\n", prog);
	printf("\nto calibrate using fixed calibration values:\n");
	printf("  %s -f -- 500 2840 3484 -3129 320 240\n", prog);
#if USE_EEPROM
	printf("\nto calibrate and write the data in eeprom:\n");
	printf("  %s -w\n", prog);
	printf("\nto calibrate from the eeprom or enter interactive");
	printf("\ncalibration if the eeprom data is not valid\n");
	printf("  %s -c\n", prog);
	printf
		("\nto use fixed calibration values and write them in eeprom:\n");
	printf("  %s -fw -- 500 2840 3484 -3129 320 240\n", prog);
#endif
	printf("\n");

	return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	int fd;
	struct de2ts_cal_params prm;
	int c, fixedCalibration = 0, invertDisplay = 0;
#if USE_EEPROM
	int eepromWrite = 0, eepromNoCheck = 1, eepromChange = 1;
#endif

	while ((c = getopt(argc, argv, "hwfci")) != EOF) {
		switch (c) {
#if !USE_EEPROM
		case 'w':
		case 'c':
			error(EXIT_FAILURE, "Eeprom device not available");
#else
		case 'w':
			eepromWrite = 1;
			break;
		case 'c':
			eepromNoCheck = 0;
			break;
#endif
		case 'f':
			fixedCalibration = 1;
			break;
		case 'i':
			invertDisplay = 1;
			break;
		default:
		case 'h':
			return usage(argv[0]);
		}
	}

	init_screen(invertDisplay);

	if ((fd = open(TOUCHSCREEN_DEVICE, O_RDONLY)) < 0)
		error(EXIT_FAILURE, "Unable to open touchscreen device");

	if (fixedCalibration) {
		int i;

		if (debug)
			debugmsg("main(): fixedCalibration\n");

		prm.version = DE2TS_VERSION;

		for (i = 0; i < 6; ++i) {
			if (optind + i >= argc)
				error(EXIT_FAILURE,
					  "Missing calibration value in the command line");
			c = atoi(argv[optind + i]);
			if (c < -4095 || c > 4095)
				error(EXIT_FAILURE,
					  "Out of bound calibration value [-4095, 4095]");
			switch (i) {
			case 0:
				prm.xoff = c;
				break;
			case 1:
				prm.xden = c;
				break;
			case 2:
				prm.yoff = c;
				break;
			case 3:
				prm.yden = c;
				break;
			case 4:
				prm.xrng = c;
				break;
			case 5:
				prm.yrng = c;
				break;
			default:
				break;
			}
		}

		if (ioctl(fd, DE2TS_CAL_PARAMS_SET, &prm) < 0)
			error(EXIT_FAILURE,
				  "Unable to set touchscreen calibration data");
	}
#if USE_EEPROM
	else if (eepromNoCheck || (eepromChange = eepromLoadContent(fd)) != 0) {
#else
	else {
#endif
		calibration(fd, &prm);
	}

#if USE_EEPROM
	/* store the data to the eeprom */
	if (eepromWrite && eepromChange) {
		eepromWriteCalData(&prm);
	}
#endif

	return EXIT_SUCCESS;
}

static void error(int code, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (errno)
		fprintf(stderr, ": %s", strerror(errno));

	fputc('\n', stderr);

	if (code)
		exit(code);
}

static void debugmsg(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
