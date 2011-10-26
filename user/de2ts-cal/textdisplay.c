/*
 *  user/de2ts-cal/textdisplay.c -- minimalist text display utility
 *
 *	Copyright (C) 2003 Georges Menie
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */

#include "screen.h"

#include "X6x13.h"
static Font X6x13 = {
	{X6x13_bits, 6, 13 * 223, 13 * 223, 1, 0},
	X6x13_offset, 6, 13, 223
};

static unsigned char notmask[8] = {
	0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe
};

static void
bitmap_copy(Bitmap * dstpsd, int dstx, int dsty, int w, int h,
			Bitmap * srcpsd, int srcx, int srcy)
{
	unsigned char *dst;
	unsigned char *src;
	int i;
	int dlinelen = dstpsd->line_length;
	int slinelen = srcpsd->line_length;

	dst = dstpsd->ptr + (dstx >> 3) + dsty * dlinelen;
	src = srcpsd->ptr + (srcx >> 3) + srcy * slinelen;
	while (--h >= 0) {
		unsigned char *d = dst;
		unsigned char *s = src;
		int dx = dstx;
		int sx = srcx;
		for (i = 0; i < w; ++i) {
			unsigned char byte;
			byte = ((*s >> (7 - (sx & 7)) & 0x01) << (7 - (dx & 7)));
			*d = dstpsd->inverted
					? (*d | ~notmask[dx & 7]) ^ byte
					: (*d & notmask[dx & 7]) | byte;
			if ((++dx & 7) == 0)
				++d;
			if ((++sx & 7) == 0)
				++s;
		}
		dst += dlinelen;
		src += slinelen;
	}
}

static void display(Font * f, char *str, int x, int y)
{
	unsigned char *ptr;
	int c, w, h;

	for (ptr = (unsigned char *) str; *ptr && x < screen.width; ptr++) {
		c = f->of[*ptr];
		w = (x + f->w) < screen.width ? f->w : screen.width - x;
		h = (y + f->h) < screen.height ? f->h : screen.height - y;
		bitmap_copy(&screen, x, y, w, h, &f->bm, 0, c);
		x += w;
	}
}

static Font *font = &X6x13;

void display_1(void)
{
	int x, y;
	char *str1 = "Touchscreen calibration";
	char *str2 = "Use stylus to tap";
	char *str3 = "center of target.";

	y = (screen.height - 3 * font->h) / 2;
	x = (screen.width - strlen(str1) * font->w) / 2;
	display(font, str1, x, y);
	x = (screen.width - strlen(str2) * font->w) / 2;
	display(font, str2, x, y + font->h);
	x = (screen.width - strlen(str3) * font->w) / 2;
	display(font, str3, x, y + 2*font->h);
}

void display_2(void)
{
	int x, y;
	char *str1 = "Touchscreen verification";

	y = (screen.height - 3 * font->h) / 2;
	x = (screen.width - strlen(str1) * font->w) / 2;
	display(font, str1, x, y);
}
