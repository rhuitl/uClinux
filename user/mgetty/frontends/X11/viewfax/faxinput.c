/* Fax file input processing
   Copyright (C) 1990, 1995, 2004  Frank D. Cringle.

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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include "faxexpand.h"

#define	FAXMAGIC	"\000PC Research, Inc\000\000\000\000\000\000"

enum { Tbyte=1, Tascii, Tshort, Tlong, Trational };
static char *typeStr[] = {
    "undef", "BYTE", "ASCII", "SHORT", "LONG", "RATIONAL" };

static char *Filename;
static int warned;

static int
errwarn(int err) {
    if (!(err || verbose)) return 0;
    if (!warned) {
	fprintf(stderr, "%s: %s: errors (E), warnings (W), info (I)\n",
		ProgName, Filename);
	warned = 1;
    }
    return 1;
}

/* Enter an argument in the linked list of pages */
struct pagenode *
notefile(char *name)
{
    struct pagenode *new = (struct pagenode *) xmalloc(sizeof *new);

    *new = defaultpage;
    if (firstpage == NULL)
	firstpage = new;
    new->prev = lastpage;
    new->next = NULL;
    new->pageno = 1;
    if (lastpage != NULL) {
	lastpage->next = new;
	new->pageno = lastpage->pageno + 1;
    }
    lastpage = new;
    new->pathname = name;
    if ((new->name = strrchr(new->pathname, '/')) != NULL)
	new->name++;
    else
	new->name = new->pathname;
    if (new->width == 0)
	new->width = 1728;
    if (new->vres > 1)
	new->vres = !(new->name[0] == 'f' && new->name[1] == 'n');
    new->extra = NULL;
    return new;
}

static t32bits
get4(unsigned char *p, int endian)
{
    return endian ? (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3] :
	p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24);
}

static int
get2(unsigned char *p, int endian)
{
    return endian ? (p[0]<<8)|p[1] : p[0]|(p[1]<<8);
}

static int
showtag(FILE *tf, int ftype, int count, t32bits pos, char *tagname)
{
    int ch;

    if ((ftype != Tascii) && errwarn(1)) {
	fprintf(stderr, "[W] %s: expected ascii tag, found %d\n",
		tagname, ftype);
	return 0;
    }
    if (fseek(tf, pos, SEEK_SET) == -1)
	return -1;
    fprintf(stderr, "[I] %s: ", tagname);
    while (count--) {
	if ((ch = fgetc(tf)) == EOF)
	    return -1;
	if (ch == 0)
	    break;
	if ((ch < ' ') || (ch > '~'))
	    ch = '?';
	fputc(ch, stderr);
    }
    if (count)
	fputs(" <short!>", stderr);
    if (ch)
	fputs(" <long!>", stderr);
    fputc('\n', stderr);
    return 0;
}

/* generate pagenodes for the images in a tiff file */
int
notetiff(char *name)
{
    FILE *tf;
    unsigned char header[8];
    static const char littleTIFF[4] = "\x49\x49\x2a\x00";
    static const char bigTIFF[4] = "\x4d\x4d\x00\x2a";
    int endian;
    t32bits IFDoff;
    struct pagenode *pn = NULL;

    if ((tf = fopen(name, "r")) == NULL) {
	perror(name);
	return 0;
    }

    if (fread(header, 8, 1, tf) == 0) {
    nottiff:
	fclose(tf);
	(void) notefile(name);
	return 0;
    }
    if (memcmp(header, &littleTIFF, 4) == 0)
	endian = 0;
    else if (memcmp(header, &bigTIFF, 4) == 0)
	endian = 1;
    else
	goto nottiff;
    IFDoff = get4(header+4, endian);
    if (IFDoff & 1)
	goto nottiff;
    Filename = name;
    warned = 0;
    do {			/* for each page */
	unsigned char buf[8];
	unsigned char *dir = NULL;
	unsigned char *dp;
	int ndirent;
	pixnum iwidth = defaultpage.width ? defaultpage.width : 1728;
	pixnum iheight = defaultpage.height ? defaultpage.height : 2339;
	int inverse = defaultpage.inverse;
	int lsbfirst = 0;
	int t4opt = 0, comp = 0;
	int orient = defaultpage.orient;
	double yres = defaultpage.vres ? 196.0 : 98.0;
	double xres;
	struct strip *strips = NULL;
	unsigned long rowsperstrip = 0;
	int nstrips = 1;

	if (fseek(tf, IFDoff, SEEK_SET) < 0) {
	realbad:
	    errwarn(1);
	    fputs("[E] invalid tiff file\n", stderr);
	bad:
	    if (strips)
		free(strips);
	    if (dir)
		free(dir);
	    fclose(tf);
	    Filename = NULL;
	    warned = 0;
	    return 1;
	}
	if (fread(buf, 2, 1, tf) == 0)
	    goto realbad;
	ndirent = get2(buf, endian);
	dir = (unsigned char *) xmalloc(12*ndirent+4);
	if (fread(dir, 12*ndirent+4, 1, tf) == 0)
	    goto realbad;
	for (dp = dir; ndirent; ndirent--, dp += 12) {
	    /* for each directory entry */
	    int tag, ftype;
	    t32bits count, value = 0;
	    tag = get2(dp, endian);
	    ftype = get2(dp+2, endian);
	    count = get4(dp+4, endian);
	    switch(ftype) {	/* value is offset to list if count*size > 4 */
	    case Tbyte:
	      break;
	    case Tascii:
		if (count <= 4)
		    value = IFDoff + 10 + dp - dir;
		else {	/* calc offset but don't read unless later used */
		    value = get4(dp+8, endian);
		}
		break;
	    case Tshort:
		value = get2(dp+8, endian);
		break;
	    case Tlong:
		value = get4(dp+8, endian);
		break;
	    case Trational:
		value = get4(dp+8, endian);
		break;
	    default:
		errwarn(1);
		fprintf(stderr, "[E] unknown ftype %d\n", ftype);
		break;
	    }
	    switch(tag) {
	    case 254:		/* NewSubFileType */
		if (errwarn(0))
		    fprintf(stderr, "[I] NewSubfile(%d) = %lu\n",
			    tag, (unsigned long) value);
		break;
	    case 256:		/* ImageWidth */
		iwidth = value;
		break;
	    case 257:		/* ImageLength */
		iheight = value;
		break;
	    case 258:		/* BitsPerSample */
		if ((value != 1) && errwarn(1))
		    fprintf(stderr, "[E] ignored Bits/Sample(%d) = %lu\n",
			    tag, (unsigned long) value);
		break;
	    case 259:		/* Compression */
		comp = value;
		break;
	    case 262:		/* PhotometricInterpretation */
		inverse ^= (value == 1);
		break;
	    case 266:		/* FillOrder */
		lsbfirst = (value == 2);
		break;
	    case 269:		/* DocumentName */
		if (verbose) {
		    if (showtag(tf, ftype, count, value, "DocumentName") < 0)
			goto realbad;
		}
		break;
	    case 270:		/* ImageDescription */
		if (verbose) {
		    if (showtag(tf, ftype, count, value,
				"ImageDescription") < 0)
			goto realbad;
		}
		break;
	    case 271:		/* Make */
		if (verbose) {
		    if (showtag(tf, ftype, count, value, "Make") < 0)
			goto realbad;
		}
		break;
	    case 272:		/* Model */
		if (verbose) {
		    if (showtag(tf, ftype, count, value, "Model") < 0)
			goto realbad;
		}
		break;
	    case 273:		/* StripOffsets */
		nstrips = count;
		strips = (struct strip *) xmalloc(count * sizeof *strips);
		if (count == 1 || (count == 2 && ftype == 3)) {
		    strips[0].offset = value;
		    if (count == 2)
			strips[1].offset = get2(dp+10, endian);
		    break;
		}
		if (fseek(tf, value, SEEK_SET) < 0)
		    goto realbad;
		for (count = 0; count < nstrips; count++) {
		    if (fread(buf, (ftype == 3) ? 2 : 4, 1, tf) == 0)
			goto realbad;
		    strips[count].offset = (ftype == 3) ?
			get2(buf, endian) : get4(buf, endian);
		}
		break;
	    case 274:		/* Orientation */
		switch(value) {
		default:	/* row0 at top,    col0 at left   */
		    orient = 0;
		    break;
		case 2:		/* row0 at top,    col0 at right  */
		    orient = TURN_M;
		    break;
		case 3:		/* row0 at bottom, col0 at right  */
		    orient = TURN_U;
		    break;
		case 4:		/* row0 at bottom, col0 at left   */
		    orient = TURN_U|TURN_M;
		    break;
		case 5:		/* row0 at left,   col0 at top    */
		    orient = TURN_M|TURN_L;
		    break;
		case 6:		/* row0 at right,  col0 at top    */
		    orient = TURN_U|TURN_L;
		    break;
		case 7:		/* row0 at right,  col0 at bottom */
		    orient = TURN_U|TURN_M|TURN_L;
		    break;
		case 8:		/* row0 at left,   col0 at bottom */
		    orient = TURN_L;
		    break;
		}
		break;
	    case 277:		/* SamplesPerPixel */
		if ((value != 1) && errwarn(1))
		    fprintf(stderr, "[I] ignored Sample/Pixel(%d) = %lu\n",
			    tag, (unsigned long) value);
		break;
	    case 278:		/* RowsPerStrip */
		rowsperstrip = value;	
		break;
	    case 279:		/* StripByteCounts */
		if ((count != nstrips) && errwarn(1)) {
		    fprintf(stderr,
			    "[E] StripsPerImage tag273=%d, tag279=%ld\n",
			    nstrips, count);
		    goto realbad;
		}
		if (count == 1 || (count == 2 && ftype == 3)) {
		    strips[0].size = value;
		    if (count == 2)
			strips[1].size = get2(dp+10, endian);
		    break;
		}
		if (fseek(tf, value, SEEK_SET) < 0)
		    goto realbad;
		for (count = 0; count < nstrips; count++) {
		    if (fread(buf, (ftype == 3) ? 2 : 4, 1, tf) == 0)
			goto realbad;
		    strips[count].size = (ftype == 3) ?
			get2(buf, endian) : get4(buf, endian);
		}
		break;
	    case 282:		/* XResolution */
		if (fseek(tf, value, SEEK_SET) < 0 ||
		    fread(buf, 8, 1, tf) == 0)
		    goto realbad;
		xres = get4(buf, endian) / get4(buf+4, endian);
		if ((xres != 204) && errwarn(0))
		    fprintf(stderr, "[W] ignored Xres(%d) = %7.2f (ns)\n",
			    tag, xres);
		break;
	    case 283:		/* YResolution */
		if (fseek(tf, value, SEEK_SET) < 0 ||
		    fread(buf, 8, 1, tf) == 0)
		    goto realbad;
		yres = get4(buf, endian) / get4(buf+4, endian);
		break;
	    case 284:		/* PlanarConfiguration */
		if ((value != 1) && errwarn(0))
		    fprintf(stderr, "[W] ignored PlanarConfig(%d) = %lu\n",
			    tag, (unsigned long) value);
		break;
	    case 285:		/* PageName */
	    case 286:		/* XPosition */
	    case 287:		/* YPosition */
		if (errwarn(0))
		    fprintf(stderr,
			    "[W] ignored storage & retrieval tag (%d)\n", tag);
		break;
	    case 292:		/* T4Options */
		t4opt = value;
		break;
	    case 293:		/* T6Options */
		if ((value != 0) && errwarn(1))
		    fprintf(stderr, "[W] ignored T6Options(%d) = %lu\n",
			    tag, (unsigned long) value);
		break;
	    case 296:		/* ResolutionUnit */
		if (value == 3)
		    yres *= 2.54;
		break;
	    case 297:		/* PageNumber */
		if (errwarn(0))
		    fprintf(stderr, "[I] PageNumber(%d) = %lu/%d\n",
			    tag, (unsigned long) value, get2(dp+10, endian));
		break;
	    case 305:		/* Software */
		if (errwarn(0)) {
		    if (showtag(tf, ftype, count, value, "Software") < 0)
			goto realbad;
		}
		break;
	    case 306:		/* DateTime */
		if (errwarn(0)) {
		    if (showtag(tf, ftype, count, value, "DateTime") < 0)
			goto realbad;
		}
		break;
	    case 315:		/* Artist */
		if (errwarn(0)) {
		    if (showtag(tf, ftype, count, value, "Artist") < 0)
			goto realbad;
		}
		break;
	    case 316:		/* HostComputer */
		if (errwarn(0)) {
		    if (showtag(tf, ftype, count, value, "HostComputer") < 0)
			goto realbad;
		}
		break;
	    case 320:		/* ColorMap */
		if (errwarn(0))
		    fprintf(stderr, "[W]ignored ColorMap(%d) = %lu\n",
			    tag, (unsigned long) value);
		break;
	    case 326:	/* BadFaxLines */
	    case 327:	/* CleanFaxData */
	    case 328:	/* ConsecutiveBadFaxLines */
		if ((value != 0) && errwarn(0))
		    fprintf(stderr, "[I] quality(%d) = %lu\n", tag,
			    (unsigned long) value);
		break;
	    default:
		if (errwarn(0)) {
		    fprintf(stderr, "[W] unknown tag %d: #%lu %s",
			    tag, (unsigned long) count, typeStr[ftype]);
		    if ((ftype == Tshort) || (ftype == Tlong))
			fprintf(stderr, " = %lu", (unsigned long) value);
		    fprintf(stderr, "\n");
		}
		break;
	    }
	}
	IFDoff = get4(dp, endian);
	free(dir);
	dir = NULL;
	if ((iwidth * iheight == 0) && errwarn(1)) {
	    fprintf(stderr,
		    "[E] fax width x height (%lu x %lu) must be non-zero\n",
		    (unsigned long) iwidth, (unsigned long) iheight);
	    goto bad;
	}
	if ((comp < 2 || comp > 4) && errwarn(1)) {
	    fprintf(stderr, "[E] compression=%d unsupported\n", comp);
	    goto bad;
	}
	pn = notefile(name);
	pn->nstrips = nstrips;
	pn->rowsperstrip = nstrips > 1 ? rowsperstrip : iheight;
	pn->strips = strips;
	pn->width = iwidth;
	pn->height = iheight;
	pn->inverse = inverse;
	pn->lsbfirst = lsbfirst;
	pn->orient = orient;
	pn->vres = (yres > 150); /* arbitrary threshold for fine resolution */
	if (comp == 2)
	    pn->expander = MHexpand;
	else if (comp == 3)
	    pn->expander = (t4opt & 1) ? g32expand : g31expand;
	else
	    pn->expander = g4expand;
    } while (IFDoff);
    fclose(tf);
    Filename = NULL;
    warned = 0;
    return 1;
}

/* report error and remove bad file from the list */
static void
badfile(struct pagenode *pn)
{
    struct pagenode *p;

    if (errno)
	perror(pn->pathname);
    if (pn == firstpage) {
	if (pn->next == NULL)
	    exit(1);
	firstpage = thispage = firstpage->next;
	firstpage->prev = NULL;
    }
    else
	for (p = firstpage; p; p = p->next)
	    if (p->next == pn) {
		thispage = p;
		p->next = pn->next;
		if (pn->next)
		    pn->next->prev = p;
		break;
	    }
    if (pn) free(pn);
}

/* rearrange input bits into t16bits lsb-first chunks */
static void
normalize(struct pagenode *pn, int revbits, int swapbytes, size_t length)
{
    t32bits *p = (t32bits *) pn->data;

    switch ((revbits<<1)|swapbytes) {
    case 0:
	break;
    case 1:
	for ( ; length; length -= 4) {
	    t32bits t = *p;
	    *p++ = ((t & 0xff00ff00) >> 8) | ((t & 0x00ff00ff) << 8);
	}
	break;
    case 2:
	for ( ; length; length -= 4) {
	    t32bits t = *p;
	    t = ((t & 0xf0f0f0f0) >> 4) | ((t & 0x0f0f0f0f) << 4);
	    t = ((t & 0xcccccccc) >> 2) | ((t & 0x33333333) << 2);
	    *p++ = ((t & 0xaaaaaaaa) >> 1) | ((t & 0x55555555) << 1);
	}
	break;
    case 3:
	for ( ; length; length -= 4) {
	    t32bits t = *p;
	    t = ((t & 0xff00ff00) >> 8) | ((t & 0x00ff00ff) << 8);
	    t = ((t & 0xf0f0f0f0) >> 4) | ((t & 0x0f0f0f0f) << 4);
	    t = ((t & 0xcccccccc) >> 2) | ((t & 0x33333333) << 2);
	    *p++ = ((t & 0xaaaaaaaa) >> 1) | ((t & 0x55555555) << 1);
	}
	break;
    default:
	fprintf(stderr, "%s: unknown rev %d\n",
		ProgName, (revbits<<1)|swapbytes);
	break;
    }
}


/* get compressed data into memory */
unsigned char *
getstrip(struct pagenode *pn, int strip)
{
    int fd, n;
    size_t offset, roundup;
    struct stat sbuf;
    unsigned char *Data;
    union { t16bits s; unsigned char b[2]; } so;
#define ShortOrder	so.b[1]

    so.s = 1;
    if ((fd = open(pn->pathname, O_RDONLY, 0)) < 0) {
	badfile(pn);
	return NULL;
    }

    if (pn->strips == NULL) {
	if (fstat(fd, &sbuf) != 0) {
	    close(fd);
	    badfile(pn);
	    return NULL;
	}
	offset = 0;
	pn->length = sbuf.st_size;
    }
    else if (strip < pn->nstrips) {
	offset = pn->strips[strip].offset;
	pn->length = pn->strips[strip].size;
    }
    else {
	fprintf(stderr, "%s:%s: trying to expand too many strips\n",
		ProgName, pn->pathname);
	close(fd);
	badfile(pn);
	return NULL;
    }
    if (!pn->length) {
	fprintf(stderr, "%s:%s: trying to expand a null strip\n",
		ProgName, pn->pathname);
	close(fd);  
	badfile(pn);
	return NULL;
    }

    /* round size to full boundary plus t32bits */
    roundup = (pn->length + 7) & ~3;

    Data = (unsigned char *) xmalloc(roundup);
    /* clear the last 2 t32bits, to force the expander to terminate
       even if the file ends in the middle of a fax line  */
    *((t32bits *) Data + roundup/4 - 2) = 0;
    *((t32bits *) Data + roundup/4 - 1) = 0;

    /* we expect to get it in one gulp... */
    if (lseek(fd, offset, SEEK_SET) < 0 ||
	(n = read(fd, Data, pn->length)) != pn->length) {
	fprintf(stderr, "%s: expected %d bytes, got %d\n",
		pn->pathname, pn->length, n);
	badfile(pn);
	free(Data);
	close(fd);
	return NULL;
    }
    close(fd);

    pn->data = (t16bits *) Data;
    if (pn->strips == NULL && memcmp(Data, FAXMAGIC, sizeof(FAXMAGIC)) == 0) {
	/* handle ghostscript / PC Research fax file */
	if (Data[24] != 1 || Data[25] != 0)
	    printf("%s: only first page of multipage file %s will be shown\n",
		   ProgName, pn->pathname);
	pn->length -= 64;
	pn->vres = Data[29] ? 1 : 0;
	pn->data += 32;
	roundup -= 64;
    }

    normalize(pn, !pn->lsbfirst, ShortOrder, roundup);
    if (pn->height == 0)
	pn->height = G3count(pn, pn->expander == g32expand);
    if (pn->height == 0) {
	fprintf(stderr, "%s: no fax found in file %s\n", ProgName,
		pn->pathname);
	errno = 0;
	badfile(pn);
	free(Data);
	return NULL;
    }
    if (pn->strips == NULL)
	pn->rowsperstrip = pn->height;
    if (verbose && strip == 0)
	printf("%s:\n\twidth = %lu\n\theight = %lu\n\tresolution = %s\n",
	       pn->name, (unsigned long) pn->width, (unsigned long) pn->height,
	       pn->vres ? "fine" : "normal");
    return Data;
}
