/* bitmap.h */
/*
Copyright 2001-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef BITMAP_H
#define BITMAP_H

typedef unsigned int  bm_uint32;
typedef signed int    bm_sint32;
typedef unsigned short bm_uint16;
typedef signed short   bm_sint16;
typedef unsigned char  bm_byte;


/* Windows/OS2 bitmap header */
typedef struct BitMapHeader {
   bm_uint32   size;
   bm_sint32   width;
   bm_sint32   height;
   bm_uint16   numBitPlanes;
   bm_uint16   numBitsPerPlane;
   bm_uint32   compressionScheme;
   bm_uint32   sizeImageData;
   bm_uint32   xResolution, yResolution;
   bm_uint32   numColorsUsed, numImportantColors;
} BITMAPHEADER;


/* OS2 bitmap header */
typedef struct BitMapHeader2 {
   bm_uint32   size;
   bm_sint16   width;
   bm_sint16   height;
   bm_uint16   numBitPlanes;
   bm_uint16   numBitsPerPlane;
} BITMAPHEADER2;


typedef struct Rgb {
   bm_byte  blue, green, red, null;
} RGB;

typedef struct Rgb2 {
   bm_byte  blue, green, red;
} RGB2;


/* common BM file header */
typedef struct BitMapFileHeader {
   bm_uint16   magic;      /* must be "BM" */
   bm_uint16   size[2];				/* actually bm_uint32 */
   bm_sint16   xHotspot, yHotspot;
   bm_uint16   offsetToBits[2];			/* actually bm_uint32 */
} BITMAPFILEHEADER;	/* needed to compensate for GCC's alignment rules */

/* LILO scheme */
typedef struct Scheme {
   short int fg, bg, sh;
   } SCHEME;

/* LILO bitmap header text color and placement parameters */
typedef struct BitmapLiloHeader {
   bm_uint16   size[2];
   char	magic[4];	/* "LILO" */

/* items below this point must correspond EXACTLY with the MENUTABLE items
   in 'common.h'
   
;*/	short row, col, ncol;		/* BMP row, col, and ncols
						mt_row:		.blkw	1
						mt_col:		.blkw	1
						mt_ncol:	.blkw	1
;*/	short maxcol, xpitch;		/* BMP max per col, xpitch between cols
						mt_maxcol:	.blkw	1
						mt_xpitch:	.blkw	1
;*/	short fg, bg, sh;		/* BMP normal text fore, backgr, shadow
						mt_fg:		.blkw	1
						mt_bg:		.blkw	1
						mt_sh:		.blkw	1
;*/	short h_fg, h_bg, h_sh;		/* highlight fg, bg, & shadow
						mt_h_fg:	.blkw	1
						mt_h_bg:	.blkw	1
						mt_h_sh:	.blkw	1
;*/	short t_fg, t_bg, t_sh;		/* timer fg, bg, & shadow colors
						mt_t_fg:	.blkw	1
						mt_t_bg:	.blkw	1
						mt_t_sh:	.blkw	1
;*/	short t_row, t_col;		/* timer position
						mt_t_row:	.blkw	1
						mt_t_col:	.blkw	1
;*/	short mincol, reserved[3];	/* BMP min per col before spill to next, reserved spacer
						mt_mincol:	.blkw	1
								.blkw	3
;*/
} BITMAPLILOHEADER;

#endif
/* end bitmap.h */
