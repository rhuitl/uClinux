/*
 * Copyright (c) 2002 Roman Wagner <rw@feith.de>
 *
 * Screen Driver, uClinux-CLEOPATRA version
 *
 * This driver requires the following CLEO entry points:
 * 	initgraph, closegraph,
 * 	putpixel, getpixel
 * 	setcolor, line, setfillstyle, bar
 *
 * All graphics drawing primitives are based on top of these functions.
 *
 * This file also contains the generalized low-level font/text
 * drawing routines, which will be split out into another file.
 * Both fixed and proportional fonts are supported.
 */

#include <stdio.h>
#include "device.h"
#include "genfont.h"

#if CLEOPATRA
 #if CLEOVERSION
 #include "cleopatra2.h"
 #else
 #include "cleopatra.h"
 #endif
#endif

/* specific CLEO driver entry points*/
static PSD  CLEO_open(PSD psd);
static void CLEO_close(PSD psd);
static void CLEO_getscreeninfo(PSD psd,PMWSCREENINFO psi);
static void CLEO_setpalette(PSD psd,int first,int count,MWPALENTRY *pal);
static void CLEO_drawpixel(PSD psd,MWCOORD x, MWCOORD y, MWPIXELVAL c);
static MWPIXELVAL CLEO_readpixel(PSD psd,MWCOORD x, MWCOORD y);
static void CLEO_drawhline(PSD psd,MWCOORD x1, MWCOORD x2, MWCOORD y, MWPIXELVAL c);
static void CLEO_drawvline(PSD psd,MWCOORD x, MWCOORD y1, MWCOORD y2, MWPIXELVAL c);
static void CLEO_fillrect(PSD psd,MWCOORD x1,MWCOORD y1,MWCOORD x2,MWCOORD y2,MWPIXELVAL c);
static void CLEO_blit(PSD dstpsd,MWCOORD destx,MWCOORD desty,MWCOORD w,MWCOORD h,
		PSD srcpsd,MWCOORD srcx,MWCOORD srcy,long op);
static PSD  CLEO_allocatememgc(PSD psd);

SCREENDEVICE	scrdev = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL,
	CLEO_open,
	CLEO_close,
	CLEO_getscreeninfo,
	CLEO_setpalette,
	CLEO_drawpixel,
	CLEO_readpixel,
	CLEO_drawhline,
	CLEO_drawvline,
	CLEO_fillrect,
	gen_fonts,
	CLEO_blit,
	NULL,			/* PreSelect*/
	NULL,			/* DrawArea subdriver*/
	NULL,			/* SetIOPermissions*/
	CLEO_allocatememgc,
	NULL,			/* MapMemGC*/
	NULL			/* FreeMemGC*/
};

//add by mlkao
extern int gr_mode;	/* temp kluge*/
//static struct linesettingstype lineinfo;
//static struct palettetype CLEO_pal;

static PSD
CLEO_open(PSD psd)
{
	psd->xres = psd->xvirtres = 800;
	psd->yres = psd->yvirtres = 600;
	psd->linelen = 800;
	psd->planes = 1;
	psd->bpp = 4;		// FIXME??
	psd->ncolors = 16;
	psd->flags = PSF_SCREEN;
	psd->addr = 0;		// FIXME

	/* note: must change psd->pixtype here for truecolor systems*/
	psd->pixtype = MWPF_PALETTE;
	return psd;
}

static void
CLEO_close(PSD psd)
{

}

static void
CLEO_getscreeninfo(PSD psd,PMWSCREENINFO psi)
{
	psi->rows = psd->yvirtres;
	psi->cols = psd->xvirtres;
	psi->planes = psd->planes;
	psi->bpp = psd->bpp;
	psi->ncolors = psd->ncolors;
	psi->pixtype = psd->pixtype;
	psi->fonts = 1;

	psi->xdpcm = 33;	/* assumes screen width of 24 cm*/
	psi->ydpcm = 33;	/* assumes screen height of 18 cm*/
}

static void
CLEO_setpalette(PSD psd,int first,int count,MWPALENTRY *pal)
{
	int i;
	MWPALENTRY *p;

	for (i = 0; i < count; i++)
   {
		p = &pal[i];
   	set_video_palette(i,p->r,p->g,p->b);
	}
	/* std 16 color palette assumed*/
}

static void
CLEO_drawpixel(PSD psd,MWCOORD x, MWCOORD y, MWPIXELVAL c)
{
	switch(gr_mode) {
		case MWMODE_SETTO1: break;
		case MWMODE_XOR: c ^= get_pixel(x, y); break;
		case MWMODE_OR:  c |= get_pixel(x, y); break;
		case MWMODE_AND: c &= get_pixel(x, y); break;
	}

	set_pixel(x, y, c);
}

static MWPIXELVAL
CLEO_readpixel(PSD psd,MWCOORD x, MWCOORD y)
{
	return get_pixel(x, y);
}

static void
CLEO_drawhline(PSD psd,MWCOORD x1, MWCOORD x2, MWCOORD y, MWPIXELVAL c)
{
	MWCOORD x;

	if (x1 > x2) {
		x  = x1;
		x1 = x2;
		x2 = x;
	}

	switch(gr_mode) {
		case MWMODE_SETTO1:
			set_colors(c,c);
			draw_x_line(x1,x2,y);
			break;
		case MWMODE_XOR:
			for(x = x1; x <= x2; x++)
				set_pixel(x, y, c ^ get_pixel(x, y));
			break;
		case MWMODE_OR:
			for(x = x1; x <= x2; x++)
				set_pixel(x, y, c | get_pixel(x, y));
			break;
		case MWMODE_AND:
			for(x = x1; x <= x2; x++)
				set_pixel(x, y, c & get_pixel(x, y));
			break;
		default:
			set_colors(c,c);
			draw_x_line(x1,x2,y);
			break;
	}
}

static void
CLEO_drawvline(PSD psd,MWCOORD x, MWCOORD y1, MWCOORD y2, MWPIXELVAL c)
{
	MWCOORD y;

	if (y1 > y2) {
		y  = y1;
		y1 = y2;
		y2 = y;
	}

	switch(gr_mode) {
		case MWMODE_SETTO1:
			set_colors(c,c);
			draw_y_line(y1,y2,x);
			break;
		case MWMODE_XOR:
			for(y = y1; y <= y2; y++)
				set_pixel(x, y, c ^ get_pixel(x, y));
			break;
		case MWMODE_OR:
			for(y = y1; y <= y2; y++)
				set_pixel(x, y, c | get_pixel(x, y));
			break;
		case MWMODE_AND:
			for(y = y1; y <= y2; y++)
				set_pixel(x, y, c & get_pixel(x, y));
			break;
		default:
			set_colors(c,c);
			draw_y_line(y1,y2,x);
			break;
	}
}

static void
CLEO_fillrect(PSD psd,MWCOORD x1, MWCOORD y1, MWCOORD x2, MWCOORD y2,
	MWPIXELVAL c)
{
	MWCOORD x, y;

	if (x1 > x2) {
		x  = x1;
		x1 = x2;
		x2 = x;
	}
	if (y1 > y2) {
		y  = y1;
		y1 = y2;
		y2 = y;
	}
	switch(gr_mode) {
		case MWMODE_SETTO1:
			set_colors(c,c);
			fill_rect(x1,y1,x2,y2);
			break;

		case MWMODE_XOR:
			for(x = x1; x <= x2; x++)
				for(y = y1; y <= y2; y++)
					set_pixel(x, y, c ^ get_pixel(x, y));
			break;

		case MWMODE_OR:
			for(x = x1; x <= x2; x++)
				for(y = y1; y <= y2; y++)
					set_pixel(x, y, c | get_pixel(x, y));
			break;

		case MWMODE_AND:
			for(x = x1; x <= x2; x++)
				for(y = y1; y <= y2; y++)
					set_pixel(x, y, c & get_pixel(x, y));
			break;

		default:
			set_colors(c,c);
			fill_rect(x1,y1,x2,y2);
			break;
	}
}

static void
CLEO_blit(PSD dstpsd,MWCOORD destx,MWCOORD desty,MWCOORD w,MWCOORD h,
		PSD srcpsd,MWCOORD srcx,MWCOORD srcy,long op)
{
	/* FIXME*/
}

/* allocate a memory screen device*/
static PSD
CLEO_allocatememgc(PSD psd)
{
	/* if driver doesn't have blit, fail*/
	return NULL;
}
