/* g3topbm.c - read a Group 3 FAX file and produce a portable bitmap *
 * 
 * Copyright (C) 1989 by Paul Haeberli <paul@manray.sgi.com>. *
 * 
 * gcc -g -o g3tolj -O2 g3tolj.c
 * 
 * Permission to use, copy, modify, and distribute this software and its *
 * documentation for any purpose and without fee is hereby granted, provided *
 * that the above copyright notice appear in all copies and that both that *
 * copyright notice and this permission notice appear in supporting *
 * documentation.  This software is provided "as is" without express or *
 * implied warranty. *
 * 
 * 
 * pbmtolj.c - read a portable bitmap and produce a LaserJet bitmap file *
 * 
 * based on pbmtops.c *
 * 
 * Michael Haberler HP Vienna mah@hpuviea.uucp * mcvax!tuvie!mah
 * 
 * misfeatures:  o positioning *
 * 
 * Bug fix Dec 12, 1988 :
 * 
 * lines in putbit() reshuffled now runs OK on HP-UX 6.0 with X10R4 and HP
 * Laserjet II
 * 
 * Bo Thide', Swedish Institute of Space Physics, Uppsala <bt@irfu.se> *
 * 
 * 
 * Copyright (C) 1988 by Jef Poskanzer and Michael Haberler.
 * 
 * Copyright (C) 1993 by Chel van Gennip. <chel@bazis.nl>
 * 
 * Update aug 31,1993, Chel van Gennip, combined g3topbm and pbmtolj, removed
 * 8MB array, added simple scaling to improve speed,
 * 
 * From: "John Watson -- Self Empl. Sys.Integrator" <watson@carssdf.uucp>
 * 
 * Date: Tue, 11 Jan 94 11:11:03 EST
 * 
 * Thankyou for sending me this conversion program.
 * 
 * I found that it generated huge files that took a long time to send to the
 * laser printer (serial port), so I added a -compress [012] option to
 * compress the data.  Not very "cute" but it works.  Some printers are not
 * capable like the Panasonic KX-P4450i, where I must still use -co 0, most
 * others can do -co 2, which is much better.
 * 
 * Update 22 may 1994 Chel van Gennip Better handling of EOF of input files
 * Support for long faxes
 *
 * $Log: g3tolj.c,v $
 * Revision 1.2  2003/10/03 11:36:02  gert
 * fix some return types and prototypes (Debian/ABA)
 *
 * Revision 1.1  2003/10/03 11:34:41  gert
 * G3 -> HP PCL bitmap, initial checkin
 *
 * 
 */

/* #include "pbm.h" */

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned char bit;

#define PBM_WHITE 0
#define PBM_BLACK 1
#define pm_error(a,b,c,d,e,f) {fprintf(stderr,a,b,c,d,e,f);fprintf(stderr,"\n");}
#define pm_message(a,b,c,d,e,f) {fprintf(stderr,a,b,c,d,e,f);fprintf(stderr,"\n");}
#define pm_usage(a) { fprintf(stderr,"usage: %s\n",a) ; exit(7) ;}
#define pbm_allocrow(a) (bit*)malloc(a)

/* g3.h - header file for group 3 FAX compression filters from pm package */

#ifndef _G3_H_
#define _G3_H_

typedef struct tableentry {
    int tabid;
    int code;
    int length;
    int count;
} tableentry;

#define TWTABLE		23
#define MWTABLE		24
#define TBTABLE		25
#define MBTABLE		26
#define EXTABLE		27
#define VRTABLE		28

static struct tableentry twtable[]=
{
    {TWTABLE, 0x35, 8, 0},
    {TWTABLE, 0x7, 6, 1},
    {TWTABLE, 0x7, 4, 2},
    {TWTABLE, 0x8, 4, 3},
    {TWTABLE, 0xb, 4, 4},
    {TWTABLE, 0xc, 4, 5},
    {TWTABLE, 0xe, 4, 6},
    {TWTABLE, 0xf, 4, 7},
    {TWTABLE, 0x13, 5, 8},
    {TWTABLE, 0x14, 5, 9},
    {TWTABLE, 0x7, 5, 10},
    {TWTABLE, 0x8, 5, 11},
    {TWTABLE, 0x8, 6, 12},
    {TWTABLE, 0x3, 6, 13},
    {TWTABLE, 0x34, 6, 14},
    {TWTABLE, 0x35, 6, 15},
    {TWTABLE, 0x2a, 6, 16},
    {TWTABLE, 0x2b, 6, 17},
    {TWTABLE, 0x27, 7, 18},
    {TWTABLE, 0xc, 7, 19},
    {TWTABLE, 0x8, 7, 20},
    {TWTABLE, 0x17, 7, 21},
    {TWTABLE, 0x3, 7, 22},
    {TWTABLE, 0x4, 7, 23},
    {TWTABLE, 0x28, 7, 24},
    {TWTABLE, 0x2b, 7, 25},
    {TWTABLE, 0x13, 7, 26},
    {TWTABLE, 0x24, 7, 27},
    {TWTABLE, 0x18, 7, 28},
    {TWTABLE, 0x2, 8, 29},
    {TWTABLE, 0x3, 8, 30},
    {TWTABLE, 0x1a, 8, 31},
    {TWTABLE, 0x1b, 8, 32},
    {TWTABLE, 0x12, 8, 33},
    {TWTABLE, 0x13, 8, 34},
    {TWTABLE, 0x14, 8, 35},
    {TWTABLE, 0x15, 8, 36},
    {TWTABLE, 0x16, 8, 37},
    {TWTABLE, 0x17, 8, 38},
    {TWTABLE, 0x28, 8, 39},
    {TWTABLE, 0x29, 8, 40},
    {TWTABLE, 0x2a, 8, 41},
    {TWTABLE, 0x2b, 8, 42},
    {TWTABLE, 0x2c, 8, 43},
    {TWTABLE, 0x2d, 8, 44},
    {TWTABLE, 0x4, 8, 45},
    {TWTABLE, 0x5, 8, 46},
    {TWTABLE, 0xa, 8, 47},
    {TWTABLE, 0xb, 8, 48},
    {TWTABLE, 0x52, 8, 49},
    {TWTABLE, 0x53, 8, 50},
    {TWTABLE, 0x54, 8, 51},
    {TWTABLE, 0x55, 8, 52},
    {TWTABLE, 0x24, 8, 53},
    {TWTABLE, 0x25, 8, 54},
    {TWTABLE, 0x58, 8, 55},
    {TWTABLE, 0x59, 8, 56},
    {TWTABLE, 0x5a, 8, 57},
    {TWTABLE, 0x5b, 8, 58},
    {TWTABLE, 0x4a, 8, 59},
    {TWTABLE, 0x4b, 8, 60},
    {TWTABLE, 0x32, 8, 61},
    {TWTABLE, 0x33, 8, 62},
    {TWTABLE, 0x34, 8, 63},
};

static struct tableentry mwtable[]=
{
    {MWTABLE, 0x1b, 5, 64},
    {MWTABLE, 0x12, 5, 128},
    {MWTABLE, 0x17, 6, 192},
    {MWTABLE, 0x37, 7, 256},
    {MWTABLE, 0x36, 8, 320},
    {MWTABLE, 0x37, 8, 384},
    {MWTABLE, 0x64, 8, 448},
    {MWTABLE, 0x65, 8, 512},
    {MWTABLE, 0x68, 8, 576},
    {MWTABLE, 0x67, 8, 640},
    {MWTABLE, 0xcc, 9, 704},
    {MWTABLE, 0xcd, 9, 768},
    {MWTABLE, 0xd2, 9, 832},
    {MWTABLE, 0xd3, 9, 896},
    {MWTABLE, 0xd4, 9, 960},
    {MWTABLE, 0xd5, 9, 1024},
    {MWTABLE, 0xd6, 9, 1088},
    {MWTABLE, 0xd7, 9, 1152},
    {MWTABLE, 0xd8, 9, 1216},
    {MWTABLE, 0xd9, 9, 1280},
    {MWTABLE, 0xda, 9, 1344},
    {MWTABLE, 0xdb, 9, 1408},
    {MWTABLE, 0x98, 9, 1472},
    {MWTABLE, 0x99, 9, 1536},
    {MWTABLE, 0x9a, 9, 1600},
    {MWTABLE, 0x18, 6, 1664},
    {MWTABLE, 0x9b, 9, 1728},
};

static struct tableentry tbtable[]=
{
    {TBTABLE, 0x37, 10, 0},
    {TBTABLE, 0x2, 3, 1},
    {TBTABLE, 0x3, 2, 2},
    {TBTABLE, 0x2, 2, 3},
    {TBTABLE, 0x3, 3, 4},
    {TBTABLE, 0x3, 4, 5},
    {TBTABLE, 0x2, 4, 6},
    {TBTABLE, 0x3, 5, 7},
    {TBTABLE, 0x5, 6, 8},
    {TBTABLE, 0x4, 6, 9},
    {TBTABLE, 0x4, 7, 10},
    {TBTABLE, 0x5, 7, 11},
    {TBTABLE, 0x7, 7, 12},
    {TBTABLE, 0x4, 8, 13},
    {TBTABLE, 0x7, 8, 14},
    {TBTABLE, 0x18, 9, 15},
    {TBTABLE, 0x17, 10, 16},
    {TBTABLE, 0x18, 10, 17},
    {TBTABLE, 0x8, 10, 18},
    {TBTABLE, 0x67, 11, 19},
    {TBTABLE, 0x68, 11, 20},
    {TBTABLE, 0x6c, 11, 21},
    {TBTABLE, 0x37, 11, 22},
    {TBTABLE, 0x28, 11, 23},
    {TBTABLE, 0x17, 11, 24},
    {TBTABLE, 0x18, 11, 25},
    {TBTABLE, 0xca, 12, 26},
    {TBTABLE, 0xcb, 12, 27},
    {TBTABLE, 0xcc, 12, 28},
    {TBTABLE, 0xcd, 12, 29},
    {TBTABLE, 0x68, 12, 30},
    {TBTABLE, 0x69, 12, 31},
    {TBTABLE, 0x6a, 12, 32},
    {TBTABLE, 0x6b, 12, 33},
    {TBTABLE, 0xd2, 12, 34},
    {TBTABLE, 0xd3, 12, 35},
    {TBTABLE, 0xd4, 12, 36},
    {TBTABLE, 0xd5, 12, 37},
    {TBTABLE, 0xd6, 12, 38},
    {TBTABLE, 0xd7, 12, 39},
    {TBTABLE, 0x6c, 12, 40},
    {TBTABLE, 0x6d, 12, 41},
    {TBTABLE, 0xda, 12, 42},
    {TBTABLE, 0xdb, 12, 43},
    {TBTABLE, 0x54, 12, 44},
    {TBTABLE, 0x55, 12, 45},
    {TBTABLE, 0x56, 12, 46},
    {TBTABLE, 0x57, 12, 47},
    {TBTABLE, 0x64, 12, 48},
    {TBTABLE, 0x65, 12, 49},
    {TBTABLE, 0x52, 12, 50},
    {TBTABLE, 0x53, 12, 51},
    {TBTABLE, 0x24, 12, 52},
    {TBTABLE, 0x37, 12, 53},
    {TBTABLE, 0x38, 12, 54},
    {TBTABLE, 0x27, 12, 55},
    {TBTABLE, 0x28, 12, 56},
    {TBTABLE, 0x58, 12, 57},
    {TBTABLE, 0x59, 12, 58},
    {TBTABLE, 0x2b, 12, 59},
    {TBTABLE, 0x2c, 12, 60},
    {TBTABLE, 0x5a, 12, 61},
    {TBTABLE, 0x66, 12, 62},
    {TBTABLE, 0x67, 12, 63},
};

static struct tableentry mbtable[]=
{
    {MBTABLE, 0xf, 10, 64},
    {MBTABLE, 0xc8, 12, 128},
    {MBTABLE, 0xc9, 12, 192},
    {MBTABLE, 0x5b, 12, 256},
    {MBTABLE, 0x33, 12, 320},
    {MBTABLE, 0x34, 12, 384},
    {MBTABLE, 0x35, 12, 448},
    {MBTABLE, 0x6c, 13, 512},
    {MBTABLE, 0x6d, 13, 576},
    {MBTABLE, 0x4a, 13, 640},
    {MBTABLE, 0x4b, 13, 704},
    {MBTABLE, 0x4c, 13, 768},
    {MBTABLE, 0x4d, 13, 832},
    {MBTABLE, 0x72, 13, 896},
    {MBTABLE, 0x73, 13, 960},
    {MBTABLE, 0x74, 13, 1024},
    {MBTABLE, 0x75, 13, 1088},
    {MBTABLE, 0x76, 13, 1152},
    {MBTABLE, 0x77, 13, 1216},
    {MBTABLE, 0x52, 13, 1280},
    {MBTABLE, 0x53, 13, 1344},
    {MBTABLE, 0x54, 13, 1408},
    {MBTABLE, 0x55, 13, 1472},
    {MBTABLE, 0x5a, 13, 1536},
    {MBTABLE, 0x5b, 13, 1600},
    {MBTABLE, 0x64, 13, 1664},
    {MBTABLE, 0x65, 13, 1728},
};

static struct tableentry extable[]=
{
    {EXTABLE, 0x8, 11, 1792},
    {EXTABLE, 0xc, 11, 1856},
    {EXTABLE, 0xd, 11, 1920},
    {EXTABLE, 0x12, 12, 1984},
    {EXTABLE, 0x13, 12, 2048},
    {EXTABLE, 0x14, 12, 2112},
    {EXTABLE, 0x15, 12, 2176},
    {EXTABLE, 0x16, 12, 2240},
    {EXTABLE, 0x17, 12, 2304},
    {EXTABLE, 0x1c, 12, 2368},
    {EXTABLE, 0x1d, 12, 2432},
    {EXTABLE, 0x1e, 12, 2496},
    {EXTABLE, 0x1f, 12, 2560},
};

#endif	/* _G3_H_ */

void skiptoeol (void);

FILE *
  pm_openr (name)
     char *name;
{
    FILE *f;

    if (strcmp (name, "-") == 0)
	f = stdin;
    else {
	f = fopen (name, "r");
	if (f == NULL) {
	    perror (name);
	    exit (1);
	}
    }
    return f;
}

int pm_keymatch (str, keyword, minchars)
     char *str;
     char *keyword;
     int minchars;
{
    register int len;

    len = strlen (str);
    if (len < minchars)
	return 0;
    while (--len >= 0) {
	register char c1, c2;

	c1 = *str++;
	c2 = *keyword++;
	if (c2 == '\0')
	    return 0;
	if (isupper (c1))
	    c1 = tolower (c1);
	if (isupper (c2))
	    c1 = tolower (c2);
	if (c1 != c2)
	    return 0;
    }
    return 1;
}

static int dpi = 300;
static int doubleheight = 1;
static hscale = 100;
static vscale = 100;
static int cmode = 0;		/* compression mode, 1=rll, 2=tiff */

static void putinit (), putbit (), putrest (), putitem ();
static int item, bitsperitem;
static char *line;
static int bytecnt;

#define TABSIZE(tab) (sizeof(tab)/sizeof(struct tableentry))
#define MAXCOLS 1728
#define MAXROWS 43000		/* up to 20 pages long */
#define MAXHIST 500

int eof = 0;
int eols;
int rawzeros;
int shdata;
int kludge;
int reversebits;
int stretch;

#define WHASHA 3510
#define WHASHB 1178

#define BHASHA 293
#define BHASHB 2695

#define HASHSIZE 1021
tableentry *whash[HASHSIZE];
tableentry *bhash[HASHSIZE];

static FILE *ifp;
static int shbit = 0;
static int eof_err = 0;

static inline int rawgetbit ()
{
    int b;

    if (eof_err) {
	rawzeros = 20;
	return (1);
    }
    if ((shbit & 0xff) == 0) {
	shdata = getc (ifp);
	if (shdata == EOF) {
	    eof_err++;
	    pm_error ("EOF / read error at line %d", eols, 0, 0, 0, 0);
	}
	shbit = reversebits ? 0x01 : 0x80;
    }
    if (shdata & shbit) {
	rawzeros = 0;
	b = 1;
    } else {
	rawzeros++;
	b = 0;
    }
    if (reversebits)
	shbit <<= 1;
    else
	shbit >>= 1;
    return b;
}

addtohash (hash, te, n, a, b)
     tableentry *hash[];
     tableentry *te;
     int n, a, b;
{
    unsigned int pos;

    while (n--) {
	pos = ((te->length + a) * (te->code + b)) % HASHSIZE;
	if (hash[pos] != 0)
	    pm_error (
			 "internal error: addtohash fatal hash collision",
			 0, 0, 0, 0, 0);
	hash[pos] = te;
	te++;
    }
}

static inline tableentry *
  hashfind (hash, length, code, a, b)
     tableentry *hash[];
     int length, code;
     int a, b;
{
    unsigned int pos;
    tableentry *te;

    pos = ((length + a) * (code + b)) % HASHSIZE;
    if (pos < 0 || pos >= HASHSIZE)
	pm_error (
	      "internal error: bad hash position, length %d code %d pos %d",
		     length, code, pos, 0, 0);
    te = hash[pos];
    return ((te && te->length == length && te->code == code) ? te : 0);
}

getfaxrow (row, bitrow)
     int row;
     bit *bitrow;
{
    int col;
    bit *bP;
    int curlen, curcode, nextbit;
    int count, color;
    tableentry *te;

    for (col = 0, bP = bitrow; col < MAXCOLS; ++col, ++bP)
	*bP = PBM_WHITE;
    col = 0;
    rawzeros = 0;
    curlen = 0;
    curcode = 0;
    color = 1;
    count = 0;
    while (!eof) {
	if (col >= MAXCOLS) {
	    skiptoeol ();
	    return (col);
	}
	do {
	    if (rawzeros >= 11) {
		nextbit = rawgetbit ();
		if (nextbit) {
		    if (col == 0)
			/* XXX should be 6 */
			eof = (++eols == 3);
		    else
			eols = 0;
#ifdef notdef
		    if (col && col < 1728)
			pm_message (
				       "warning, row %d short (len %d)",
				       row, col, 0, 0, 0);
#endif	/* notdef */
		    return (col);
		}
	    } else
		nextbit = rawgetbit ();
	    curcode = (curcode << 1) + nextbit;
	    curlen++;
	} while (curcode <= 0);
	if (curlen > 13) {
	    pm_message (
			   "bad code word at row %d, col %d (len %d code 0x%x), skipping to EOL",
			   row, col, curlen, curcode, 0);
	    skiptoeol ();
	    return (col);
	}
	if (color) {
	    if (curlen < 4)
		continue;
	    te = hashfind (whash, curlen, curcode, WHASHA, WHASHB);
	} else {
	    if (curlen < 2)
		continue;
	    te = hashfind (bhash, curlen, curcode, BHASHA, BHASHB);
	}
	if (!te)
	    continue;
	switch (te->tabid) {
	case TWTABLE:
	case TBTABLE:
	    count += te->count;
	    if (col + count > MAXCOLS)
		count = MAXCOLS - col;
	    if (count > 0) {
		if (color) {
		    col += count;
		    count = 0;
		} else {
		    for (; count > 0; --count, ++col)
			bitrow[col] = PBM_BLACK;
		}
	    }
	    curcode = 0;
	    curlen = 0;
	    color = !color;
	    break;
	case MWTABLE:
	case MBTABLE:
	    count += te->count;
	    curcode = 0;
	    curlen = 0;
	    break;
	case EXTABLE:
	    count += te->count;
	    curcode = 0;
	    curlen = 0;
	    break;
	default:
	    pm_error ("internal bad poop", 0, 0, 0, 0, 0);
	}
    }
    return (0);
}

void skiptoeol ()
{
    while (rawzeros < 11)
	(void) rawgetbit ();
    for (;;) {
	if (rawgetbit ())
	    break;
    }
}


static void putinit ()
{
    /* Printer reset. */
    printf ("\033E");
    printf ("\033*rB");

    printf ("\033*t%dR", dpi);	/* Set raster graphics resolution */
    /* move to top left of page & set current position */
    printf ("\033&l26A");	/* A4 size */
    printf ("\033&l0L");	/* Don't skip perforation */
    printf ("\033&l0E");	/* Top margin 0 */
    printf ("\033*p0x0Y");
    printf ("\033*r1A");	/* Start raster graphics, relative adressing */
    /* printf("\033*b2M"); */
    printf ("\033*b%dM", cmode);/* set compression mode, 1=rll */
}

int o_item = -1;
int oo_item = -1;
char *cb;			/* command byte */

static void putitem ()
{
    if (cmode == 1) {
	if (item == o_item && ((unsigned char) (line[bytecnt - 2]) < 255)) {
	    ++line[bytecnt - 2];
	    bitsperitem = item = 0;
	    return;
	}
	line[bytecnt++] = 0;	/* repeat count of one */
	line[bytecnt++] = o_item = item;
	bitsperitem = 0;
	item = 0;
	return;
    }
    if (cmode == 2) {
	/* if running repeat, continue if same char again */
	if (item == o_item && cb != NULL && *cb < 1 && *cb > -127) {
	    --*cb;
	    bitsperitem = item = 0;
	    return;
	}
	/* if running literal see last two same as next and switch to repeat */
	if (cb != NULL && *cb > 0 && o_item == oo_item && o_item == item) {
	    *cb -= 2;
	    cb = &line[bytecnt - 2];
	    *cb = -2;
	    bitsperitem = item = 0;
	    return;
	}
	/* if running literal add next byte to string */
	if (cb != NULL && *cb >= 0 && *cb < 127) {
	    ++*cb;
	    oo_item = o_item;
	    line[bytecnt++] = o_item = item;
	    bitsperitem = item = 0;
	    return;
	}
	/* start new literal */
	cb = &line[bytecnt];
	line[bytecnt++] = 0;	/* repeat count of one */
	line[bytecnt++] = o_item = item;
	oo_item = -1;
	bitsperitem = 0;
	item = 0;
	return;
    }
    line[bytecnt++] = item;
    bitsperitem = 0;
    item = 0;
}

static void putbit (b)
     bit b;
{
    if (b == PBM_BLACK)
	item += 1 << (7 - bitsperitem);
    bitsperitem++;
    if (bitsperitem == 8) {
	putitem ();
    }
}

static void putrest ()
{
    /* end raster graphics */
    printf ("\033*rB");

    /* Printer reset. */
    printf ("\033E");
}

static struct {
    int bytecnt;
    char *line;
} hist[MAXHIST];
static int maxhist = MAXHIST;
static int histidx = 0;
static int lncnt = 0;
static int maxline = 11 * 300;

newpage (FILE * fd)
{
    int i;

    putrest ();
    putinit ();
    lncnt = 0;
    for (i = 0; i < maxhist; i++) {
	fprintf (fd, "\033*b%dW", hist[histidx].bytecnt);
	fwrite (hist[histidx].line, sizeof (char), hist[histidx].bytecnt, fd);

	histidx++;
	if (histidx >= maxhist)
	    histidx = 0;
	lncnt++;
    }
}
static void lj_writerow (FILE * fd, bit * writerow, int wcols)
{
    int i;

    oo_item = o_item = -1;
    cb = NULL;
    item = 0;
    bytecnt = 0;
    bitsperitem = 0;
    for (i = 0; i < wcols; i++)
	putbit (writerow[i]);
    if (bitsperitem > 0)
	putitem ();
    fprintf (fd, "\033*b%dW", bytecnt);
    fwrite (line, sizeof (char), bytecnt, fd);

    hist[histidx].bytecnt = bytecnt;
    histidx++;
    if (histidx >= maxhist)
	histidx = 0;
    line = hist[histidx].line;
    lncnt++;
    if (lncnt > maxline)
	newpage (fd);
};

int main (argc, argv)
    int argc;
    char *argv[];
{
    int argn, rows, wrows, cols, wcols, row, wrow, col, wcol, i;
    int vval, hval;
    bit *readrow, *writerow, *bP, *wbP, bitval;
    float aspect, scale, pagelength, duplength;
    int format;
    register int nzcol;

    char *usage =
    " g3tolj [-kludge] [-reversebits] [-scale N] [-aspect N]"
    "\n\t[-resolution 75|100|150|300] [-compress 0|1|2] [-pagelength N]"
    "\n\t[-duplength N] [g3file]"
    "\n\tDefaults -sc 1.4 -as 1.0 -re 300 -co 0 -pa 10.95 -du 0.7";

    argn = 1;
    kludge = 0;
    reversebits = 0;
    aspect = 1.0;
    scale = 1.4;
    pagelength = 10.95;
    duplength = 0.7;

    /* Check for flags. */
    while (argn < argc && argv[argn][0] == '-' && argv[argn][1] != '\0') {
	if (pm_keymatch (argv[argn], "-kludge", 2))
	    kludge = 1;
	else if (pm_keymatch (argv[argn], "-reversebits", 2))
	    reversebits = 1;
	else if (pm_keymatch (argv[argn], "-resolution", 2)) {
	    ++argn;
	    if (argn == argc || sscanf (argv[argn], "%d", &dpi) != 1)
		pm_usage (usage);
	} else if (pm_keymatch (argv[argn], "-aspect", 2)) {
	    ++argn;
	    if (argn == argc || sscanf (argv[argn], "%f", &aspect) != 1)
		pm_usage (usage);
	} else if (pm_keymatch (argv[argn], "-scale", 2)) {
	    ++argn;
	    if (argn == argc || sscanf (argv[argn], "%f", &scale) != 1)
		pm_usage (usage);
	} else if (pm_keymatch (argv[argn], "-compress", 2)) {
	    ++argn;
	    if (argn == argc || sscanf (argv[argn], "%d", &cmode) != 1)
		pm_usage (usage);
	    if ((cmode < 0) || (cmode > 2))
		pm_usage (usage);
	} else if (pm_keymatch (argv[argn], "-duplength", 2)) {
	    ++argn;
	    if (argn == argc || sscanf (argv[argn], "%f", &duplength) != 1)
		pm_usage (usage);
	} else if (pm_keymatch (argv[argn], "-pagelength", 2)) {
	    ++argn;
	    if (argn == argc || sscanf (argv[argn], "%f", &pagelength) != 1)
		pm_usage (usage);
	} else
	    pm_usage (usage);
	argn++;
    }

    if (argn < argc) {
	ifp = pm_openr (argv[argn]);
	argn++;
    } else
	ifp = stdin;

    if (argn != argc)
	pm_usage (usage);

    vscale = aspect * scale * 100;
    hscale = scale * 100;
    eols = 0;
    maxhist = duplength * dpi;
    if (maxhist > MAXHIST)
	maxhist = MAXHIST;


    for (i = 0; i < maxhist; i++) {
	hist[i].line = (char *) malloc (2 * (dpi * 10 * hscale) / 100);
    }
    histidx = 0;
    lncnt = 0;
    maxline = pagelength * dpi;
    line = hist[histidx].line;
    putinit ();

    if (kludge) {
	/* Skip extra lines to get in sync. */
	skiptoeol ();
	skiptoeol ();
	skiptoeol ();
    }
    skiptoeol ();
    for (i = 0; i < HASHSIZE; ++i)
	whash[i] = bhash[i] = (tableentry *) 0;
    addtohash (whash, twtable, TABSIZE (twtable), WHASHA, WHASHB);
    addtohash (whash, mwtable, TABSIZE (mwtable), WHASHA, WHASHB);
    addtohash (whash, extable, TABSIZE (extable), WHASHA, WHASHB);
    addtohash (bhash, tbtable, TABSIZE (tbtable), BHASHA, BHASHB);
    addtohash (bhash, mbtable, TABSIZE (mbtable), BHASHA, BHASHB);
    addtohash (bhash, extable, TABSIZE (extable), BHASHA, BHASHB);

    wcols = (MAXCOLS * hscale) / 100;
    wrows = 99999;
    writerow = pbm_allocrow (wcols);
    readrow = pbm_allocrow (MAXCOLS);
    vval = wrow = row = 0;
    while (row < MAXROWS) {
	for (col = 0, bP = writerow; col < (MAXCOLS * hscale) / 100;
	     ++col, ++bP)
	    *bP = PBM_WHITE;
	cols = 1;
	while (vval < 100) {
	    if (row < MAXROWS) {
		hval = wcol = 0;
		bP = readrow;
		wbP = writerow;
		col = getfaxrow (row, readrow);
		col--;
		while ((col > 0) && (readrow[col] == PBM_WHITE))
		    col--;
		col++;
		if (col > cols)
		    cols = col;
		wcols = (cols * hscale) / 100;
		col = 0;
		while (col < cols) {
		    bitval = *wbP;
		    while (hval < 100) {
			if (col++ < cols)
			    if (*bP++ == PBM_BLACK)
				bitval = PBM_BLACK;
			hval += hscale;
		    }
		    while (hval >= 100) {
			if (wcol++ < wcols)
			    *wbP++ = bitval;
			hval -= 100;
		    }
		}		/* while(col */
	    }			/* if(row */
	    vval += vscale;
	    row++;
	}			/* while vval */
	while (vval >= 100) {
	    if (wrow < wrows) {
		lj_writerow (stdout, writerow, wcols);
		wrow++;
	    }
	    vval -= 100;
	}
	if (eof)
	    break;
    }
    putrest ();

    return 0;
}
