/* Include file for fax routines
   Copyright (C) 1990, 1995  Frank D. Cringle.

This file is part of viewfax - g3/g4 fax processing software.
     
viewfax is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.
     
This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.
     
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */

#include <limits.h>

#if ULONG_MAX == 4294967295UL
typedef unsigned long t32bits;
#elif UINT_MAX == 4294967295UL
typedef unsigned int t32bits;
#else
#error need a 32-bit unsigned type
/* if you see the above error, add an #elif case for your architecture
   and tell fdc@cliwe.ping.de about it */
#endif

#if USHRT_MAX == 65535
typedef unsigned short t16bits;
#elif UINT_MAX == 65535
typedef unsigned int t16bits;
#else
#error need a 16-bit unsigned type
/* if you see the above error, add an #elif case for your architecture
   and tell fdc@cliwe.ping.de about it */
#endif
typedef t16bits pixnum;

struct pagenode;

/* drawfunc() points to a function which processes a line of the
   expanded image described as a list of run lengths.
   run is the base of an array of lengths, starting with a
   (possibly empty) white run for line number linenum.
   pn points to the page descriptor */
typedef void (*drawfunc)(pixnum *run, int linenum, struct pagenode *pn);

struct strip {			/* tiff strip descriptor */
    off_t offset;		/* offset in file */
    off_t size;			/* size of this strip */
};

struct pagenode {		/* compressed page descriptor */
    struct pagenode *prev, *next; /* list links */
    char *name;			/* basename of file */
    char *pathname;		/* full name of file */
    int pageno;			/* page number */
    int	nstrips;		/* number of strips */
    int rowsperstrip;		/* number of rows per strip */
    int stripnum;		/* current strip while expanding */
    struct strip *strips;	/* array of strips containing fax data in file */
    t16bits *data;		/* in-memory copy of strip */
    size_t length;		/* length of data */
    pixnum width;		/* width of page in pixels */
    pixnum height;		/* height of page in lines */
    char inverse;		/* black <=> white */
    char lsbfirst;		/* bit order is lsb first */
    char orient;		/* orientation - upsidedown, landscape, mirrored */
    char vres;			/* vertical resolution: 1 = fine  */
    void (*expander)(struct pagenode *, drawfunc);
    void *extra;		/* used for Ximage */
};
extern struct pagenode *firstpage, *lastpage, *thispage;
extern struct pagenode defaultpage;

/* page orientation flags */
#define TURN_U	1
#define TURN_L	2
#define TURN_M	4

extern char *ProgName;

/* fsm state codes */
#define S_Null		0
#define S_Pass		1
#define S_Horiz		2
#define S_V0		3
#define S_VR		4
#define S_VL		5
#define S_Ext		6
#define S_TermW		7
#define S_TermB		8
#define S_MakeUpW	9
#define S_MakeUpB	10
#define S_MakeUp	11
#define S_EOL		12

/* state table entry */
struct tabent {
    unsigned char State;
    unsigned char Width;	/* width of code in bits */
    pixnum Param;		/* run length */
};

extern struct tabent MainTable[]; 	/* 2-D state table */
extern struct tabent WhiteTable[];	/* White run lengths */
extern struct tabent BlackTable[];	/* Black run lengths */

extern int verbose;

void MHexpand(struct pagenode *pn, drawfunc df);
void g31expand(struct pagenode *pn, drawfunc df);
void g32expand(struct pagenode *pn, drawfunc df);
void g4expand(struct pagenode *pn, drawfunc df);

unsigned char * getstrip(struct pagenode *pn, int strip);
struct pagenode *notefile(char *name);
int notetiff(char *name);

/* initialise code tables */
extern void faxinit(void);
/* count lines in image */
extern int G3count(struct pagenode *pn, int twoD);

/* get memory or abort if none available */
extern char *xmalloc(unsigned int size);

#ifdef linux
#define _HAVE_USLEEP
#endif

#if defined(BSD) || defined(__FreeBSD__) || defined(_BSD_SOURCE)
#define _HAVE_USLEEP
#ifndef rindex
#define rindex strrchr
#endif
#ifndef bcmp
#define memcmp bcmp
#endif
#define memclr(p,n)	bzero(p,n)
#else  /* not BSD */
#define memclr(p,n)	memset(p,0,n)
#endif
