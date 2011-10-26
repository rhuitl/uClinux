/* edit.c -- bitmap file manipulation and editing */
/*
Copyright 2002-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#ifdef	_SYS_STATFS_H
#define	_I386_STATFS_H	/* two versions of statfs is not good ... */
#endif

#include "config.h"
#include "lilo.h"
#include "common.h"
#include "cfg.h"
#include "temp.h"
#include "bsect.h"
#include "bitmap.h"
#include "edit.h"


#define USE_BSECT_PW_INPUT 0		/* use another's input routine */
#define BMP_CONF ".dat"
#define BMP_BMP  ".bmp"
#define NPALETTE 256

/* Luminance of a color 0..255 -- YIQ color model */
#define Y(c) (((c).red*0.30+(c).green*0.59+(c).blue*0.11)/255)
#define NORM(x) ((float)(x)/255.0)

static BITMAPFILEHEADER fh;
static BITMAPHEADER bmh;
static RGB palette[NPALETTE];
static int filepos, npal;

static BITMAPLILOHEADER lh0 = {
	{sizeof(BITMAPLILOHEADER), 0}, "LILO",
	5*16, 12*8, 1,			/* row, col, ncol */
	25, (MAX_IMAGE_NAME+1)*8,	/* maxcol, xpitch */
	7, 7, 7,			/* normal text fg, bg, shadow */
	15, 15, 15,			/* highlight  fg, bg, shadow  */
	7, 0, 7,			/* timer text  fg, bg, shadow */
	2*16, 64*8,			/* timer row, col */
	4, {0, 0, 0}			/* mincol, reserved[3] */
		};



#if USE_BSECT_PW_INPUT
#define getLine pw_input
#else
static char *getLine(void)
{
    char *pass;
    char buf[MAX_TOKEN+1];
    int i, ch;
    
    i = 0;
    fflush(stdout);
    while((ch=getchar())!='\n') if (i<MAX_TOKEN) buf[i++]=ch;
    buf[i]=0;
    pass = stralloc(buf);
/*    while (i) buf[--i]=0;	*/
    return pass;
}
#endif


int get_std_headers(int fd,
	BITMAPFILEHEADER *fh,
	BITMAPHEADER *bmh,
	BITMAPLILOHEADER *lh)
{
    short size;
    BITMAPHEADER2 bmh2;
    int n, i;
    
    lseek(fd, 0, SEEK_SET);
    if (read(fd, (void*)fh, sizeof(BITMAPFILEHEADER)) !=
			sizeof(BITMAPFILEHEADER) )  return -1;
    if (fh->magic != 0x4D42 /* "BM" */)  return 1;
    if (read(fd, &size, sizeof(size)) != sizeof(size))   return -1;
    if (size==sizeof(BITMAPHEADER2)) { /* an OS/2 bitmap */
	if (read(fd, (void*)&bmh2+sizeof(size), sizeof(BITMAPHEADER2)-sizeof(size))
		!= sizeof(BITMAPHEADER2)-sizeof(size) )   return -1;
	memset(bmh, 0, sizeof(BITMAPHEADER));
	bmh->width = bmh2.width;
	bmh->height = bmh2.height;
	n = bmh->numBitPlanes = bmh2.numBitPlanes;
	n *= bmh->numBitsPerPlane = bmh2.numBitsPerPlane;
	bmh->numColorsUsed = bmh->numImportantColors = 1 << n;
	bmh->sizeImageData = *(int*)(fh->size) - *(int*)(fh->offsetToBits);
	bmh->size = sizeof(*bmh);    /* new size!! */
	n = sizeof(RGB2);
    }
    else if (size==sizeof(BITMAPHEADER)) {
	if (read(fd, (void*)bmh+sizeof(size), sizeof(BITMAPHEADER)-sizeof(size))
		!= sizeof(BITMAPHEADER)-sizeof(size) )   return -1;
	bmh->size = size;
	n = sizeof(RGB);
    }
    else  return 2;

    *lh = lh0;
    npal = 1 << (bmh->numBitPlanes * bmh->numBitsPerPlane);
    colormax = npal - 1;
    if (npal > nelem(palette) )   return 3;
    for (i=0; i<npal; i++) {
	if (read(fd, &palette[i], n) != n)  return -1;
	if (n==sizeof(RGB2)) palette[i].null = 0;
    }
    if (*(int*)(fh->offsetToBits) == sizeof(BITMAPFILEHEADER) +
    		sizeof(BITMAPHEADER) + sizeof(BITMAPLILOHEADER) +
    		npal*sizeof(RGB) )  /* test will fail for OS/2 bitmaps */ {
      /* get probable BITMAPLILOHEADER */
	if (read(fd, &size, sizeof(size)) != sizeof(size))  return -1;
	if (size != sizeof(BITMAPLILOHEADER))   return 4;
	if (read(fd, (void*)lh+sizeof(size), sizeof(*lh)-sizeof(size)) !=
		sizeof(*lh)-sizeof(size))  return -1;
	*(int*)(lh->size) = size;
	if (strncmp(lh->magic, "LILO", 4) != 0)   return 5;
    } else { /* there is no BITMAPLILOHEADER present */
#ifdef STANDALONE
        printf("No BITMAPLILOHEADER\n");
#endif
    }

/* file is left positioned at the start of the bitmap data */
    filepos = lseek(fd, 0, SEEK_CUR);
    return 0;
}


int put_std_bmpfile(int fd, int ifd,
	BITMAPFILEHEADER *fh,
	BITMAPHEADER *bmh,
	BITMAPLILOHEADER *lh)
{
    int n, total, npalette;
    char buf[1024];
    
    npalette = 1 << (bmh->numBitPlanes * bmh->numBitsPerPlane);
    write(fd, fh, sizeof(*fh));
    write(fd, bmh, sizeof(*bmh));
    write(fd, palette, npalette*sizeof(palette[0]));
    write(fd, lh, sizeof(*lh));
    total=0;
    lseek(ifd, filepos, SEEK_SET);
    do {
	n = read(ifd, buf, sizeof(buf));
	if (n>0) {
	    if (write(fd, buf, n) != n)  return -1;
	    total += n;
	}
	else if (n<0)  printf("Error reading input\n");
    } while (n>0);
    bmh->sizeImageData = total;
    *(int*)(fh->offsetToBits) = n = sizeof(BITMAPFILEHEADER) +
    		sizeof(BITMAPHEADER) + sizeof(BITMAPLILOHEADER) +
    		npalette*sizeof(RGB);
    *(int*)(fh->size) = total + n;
    lseek(fd, 0, SEEK_SET);
    write(fd, fh, sizeof(*fh));
    write(fd, bmh, sizeof(*bmh));

    return 0;
}


#ifndef STANDALONE
static	char *temp_file, *bitmap_file;
static	int ifd, ofd;
static	union {
	   unsigned char buffer[256];
	   MENUTABLE mt;
	   BITMAPLILOHEADER bmlh;
	} tm;
static	MENUTABLE *menu = &tm.mt;
static	BITMAPLILOHEADER *lh = (void*)tm.buffer + 
    			((long)&tm.mt.row - (long)&tm.bmlh.row);

/* a convenience definition */
#define mn tm.mt

/* timer = 1 if timer is enabled, 0 if timer is disabled */
#define timer (mn.t_row>=0)

static int yesno(char *query, int def)
{
    char *yn;
    int ans = 2;

    while (ans>1) {    
	printf("%s (yes or no) [%c]:  ", query, def?'Y':'N');
	yn = getLine();
	if (!*yn) ans = def;
	else if (toupper(*yn) == 'Y') ans = 1;
	else if (toupper(*yn) == 'N') ans = 0;
	free(yn);
    }
    return ans;
}


static void dat_file_creat(char *bmp)
{
    char *datfile;
    FILE *fdat;
    
    datfile = stralloc(bmp);
    *strrchr(datfile,*(BMP_BMP)) = 0;
    strcat(datfile, BMP_CONF);
    if (!(fdat = fopen(datfile, "w"))) pdie("Open .dat file");

    fprintf(fdat,"#\n# generated companion file to:\n#\n");
    fprintf(fdat,"bitmap = %s\n", bmp);
    
    fprintf(fdat,"bmp-table = %d%s,%d%s;%d,%d,%d%s,%d\n",
    	mn.col%8 ? mn.col : mn.col/8+1,
    	mn.col%8 ? "p" : "",
    	mn.row%16 ? mn.row : mn.row/16+1,
    	mn.row%16 ? "p" : "",
    	mn.ncol,
    	mn.maxcol,
    	mn.xpitch%8 ? mn.xpitch : mn.xpitch/8,
    	mn.xpitch%8 ? "p" : "",
    	mn.mincol );
    
    fprintf(fdat,"bmp-colors = %d,", mn.fg);
    if (mn.bg != mn.fg) fprintf(fdat,"%d",mn.bg);
    putc(',',fdat);
    if (mn.sh != mn.fg) fprintf(fdat,"%d",mn.sh);
    putc(';',fdat);
    fprintf(fdat,"%d,", mn.h_fg);
    if (mn.h_bg != mn.h_fg) fprintf(fdat,"%d",mn.h_bg);
    putc(',',fdat);
    if (mn.h_sh != mn.h_fg) fprintf(fdat,"%d",mn.h_sh);
    putc('\n',fdat);

    fprintf(fdat,"bmp-timer = ");
    if (mn.t_row < 0) fprintf(fdat,"none\n");
    else {
	fprintf(fdat,"%d%s,%d%s;%d,",
	    mn.t_col%8 ? mn.t_col : mn.t_col/8+1,
	    mn.t_col%8 ? "p" : "",
	    mn.t_row%16 ? mn.t_row : mn.t_row/16+1,
	    mn.t_row%16 ? "p" : "",
	    mn.t_fg );
	if (mn.t_bg != mn.t_fg) fprintf(fdat,"%d", mn.t_bg);
	putc(',',fdat);
	if (mn.t_sh != mn.t_fg) fprintf(fdat,"%d", mn.t_sh);
	putc('\n',fdat);
    }
    fclose(fdat);
}

static void bmp_file_open(char *bmp)
{
    int n;

    bitmap_file = bmp;
    temp_file = strcat(strcpy(alloc(strlen(bitmap_file)+strlen(MAP_TMP_APP)+1),
    			      bitmap_file),
    		       MAP_TMP_APP);
    ifd = open(bitmap_file, O_RDONLY);
    if (ifd<0) pdie("Cannot open bitmap file");
    ofd = open(temp_file, O_CREAT|O_WRONLY, 0644);
    if (ofd<0) pdie("Cannot open temporary file");
    temp_register(temp_file);
    
    n = get_std_headers(ifd, &fh, &bmh, lh);
    if (verbose >= 3) printf("get_std_headers:  returns %d\n", n);
    
    if (n<0) die("read file '%s': %s", bitmap_file, strerror(errno));
    switch (n) {
    	case 1:
    	case 2:
    	    die("Not a bitmap file '%s'", bitmap_file);
    	case 3:
    	    die("Unsupported bitmap file '%s' (%d bit color)", bitmap_file,
    	    	bmh.numBitPlanes*bmh.numBitsPerPlane);
    	case 4:
    	case 5:
    	    die("Unrecognized auxiliary header in file '%s'", bitmap_file);
    	default:
    	    ;
    }
}


static void bmp_file_close(int update)
{
    int n;
    
    if (update) n = put_std_bmpfile(ofd, ifd, &fh, &bmh, lh);
    
    close(ifd);
    close(ofd);
    temp_unregister(temp_file);
    if (!update || test) {
	if (verbose < 9) remove(temp_file);
    } else {
	n = rename(temp_file, bitmap_file);
    }
}


static void location(char *what, short x, short y)
{
    printf("%sColumn(X): %d%s (chars) or %hdp (pixels)", what, x/8+1, x%8?"+":"", x);
    printf("   Row(Y): %d%s (chars) or %hdp (pixels)\n", y/16+1, y%16?"+":"", y);
}


static void color(char *what, short fg, short bg, short sh)
{
static char sp[] = "   ";

    printf("%sForeground: %hd%sBackground: ", what, fg, sp);
    if (bg==fg) printf("transparent%s",sp);
    else printf("%hd%s", bg, sp);
    printf("Shadow: ");
    if (sh==fg) printf("none\n");
    else printf("%hd\n", sh);
}


static void get3colors(char *what, short *color)
{
static char *co[] = { "fg", "bg", "sh" };
static char *op[] = { "", ",transparent", ",none" };
    int i;
    int tr, no;
    unsigned int c;
    char n[4], *line, *end;
    int dcol[3];

    for (i=0; i<3; i++) dcol[i] = color[i];	/* save inputs */
    tr = (dcol[0] == dcol[1]);
    no = (dcol[0] == dcol[2]);
    
    printf("\n");
    for (i=0; i<3; i++) {
	sprintf(n, "%hd", dcol[i]);
	printf("%s text %s color (0..%d%s) [%s]: ", what, co[i], npal-1, op[i],
		i==1 && tr ? "transparent" :
		i==2 && no ? "none" : n);
	line = getLine();
	if (!*line) c = dcol[i];
	else if (toupper(*line)=='T' && i==1) c = color[0];
	else if (toupper(*line)=='N' && i==2) c = color[0];
	else {
	    c = strtol(line, &end, 0);
	    if (line==end || c>=npal || *end) {
		c = dcol[i];
		printf("???\n");
	    }
	}
	color[i] = c;
	free(line);
	if (i==0) {
	    if (tr) dcol[1]=c;
	    if (no) dcol[2]=c;
	}
    }
}


static void number(char *what, short *num, int min, int max)
{
    char *line, *end;
    int val;
    
    printf("%s (%d..%d) [%hd]:  ", what, min, max, *num);
    line = getLine();
    if (!*line) val = *num;
    else {
	val = strtol(line, &end, 0);
	if (val < min || val > max || *end) {
	    printf("???");
	    val = *num;
	}
    }
    free(line);
    *num = val;
}


static void getXY(char *what, short *locp, int scale, int abs)
{
    char *line, *end;
    int val;
    int min = abs ? 1 : MAX_IMAGE_NAME;
    int minp = min*scale;
    int max = scale==8 ? 80 : 30;
    int maxp = (max-abs)*scale;
    int loc = *locp/scale + abs;
    char *plus = *locp%scale ? "+" : "";
    
    printf("%s (%d..%d) or (%dp..%dp) [%d%s or %dp]: ", what,
    			min, max, minp, maxp, loc, plus, (int)*locp);
    
    line = getLine();
    if (!*line) val = *locp;
    else {
	val = strtol(line, &end, 0);
	if (line==end || (*end && toupper(*end)!='P')) {
	    val = *locp;
	    printf("???1\n");
	}
	if (toupper(*end)!='P') val = (val-1)*scale;
	if (val > maxp) {
	    val = *locp;
	    printf("???2\n");
	}
    }
    *locp = val;
    free(line);
}


static void show_timer(void)
{
    if (timer) {
	color("    Timer:  ", mn.t_fg, mn.t_bg, mn.t_sh);
	location("Timer position:\n  ", mn.t_col, mn.t_row);
    }
    else
    {
	printf("\n\tThe timer is DISABLED.\n");
    }
}


static void show_colors(int timopt)
{
    color("   Normal:  ", mn.fg, mn.bg, mn.sh);
    color("Highlight:  ", mn.h_fg, mn.h_bg, mn.h_sh);
    if (timopt && timer)
	color("    Timer:  ", mn.t_fg, mn.t_bg, mn.t_sh);
}

static void show_layout(void)
{
    printf("\nTable dimensions:\n");
    printf("  Number of columns:  %hd\n",  mn.ncol);
    printf("  Entries per column (number of rows):  %hd\n", mn.maxcol);
    if (mn.ncol > 1) {
	printf(	"  Column pitch (X-spacing from character 1 of one column to character 1\n"
		"      of the next column):  %d%s (chars)  %hdp (pixels)\n", mn.xpitch/8,
    		mn.xpitch%8 ? "+" : "", mn.xpitch);
    	printf( "  Spill threshold (number of entries filled-in in the first column\n"
    		"      before entries are made in the second column):  %hd\n", mn.mincol);
    }
    location("Table upper left corner:\n  ", mn.col, mn.row);
}


static void edit_timer(void)
{
    char *cmd;
    int editing = 1;
    
    do {
    	if (timer) printf("\nTimer colors:\n");
    	show_timer();
    	printf("\nTimer setup:  ");
    	
	if (timer) printf("C)olors, P)osition, D)isable");
	else printf("E)nable");
	
	printf(", B)ack:  ");
	
	cmd = getLine();
	
	if (timer) switch(toupper(*cmd)) {
	    case 'C':
		get3colors("Timer", &mn.t_fg);
		break;
	    case 'D':
		while (timer) {
		    mn.t_row -= 480;
		}
		break;
	    case 'P':
		getXY("\nTimer col", &mn.t_col, 8, 1);
		getXY("Timer row", &mn.t_row, 16, 1);
		break;
	    case 'B':
		editing = 0;
		break;
	    default:
	    	printf("???");
	}
	else switch(toupper(*cmd)) {
	    case 'E':
		while (!timer) {
		    mn.t_row += 480;
		}
		break;
	    case 'B':
		editing = 0;
		break;
	    default:
	    	printf("???");
	}
	free(cmd);
	printf("\n");
    } while (editing);
}


static void edit_layout(void)
{
    char *cmd;
    int editing = 1;
    
    do {
	show_layout();
    	
	printf("\nLayout options:  D)imensions, P)osition, B)ack:  ");

	cmd = getLine();
	switch(toupper(*cmd)) {
	    case 'D':
		number("\nNumber of columns", &mn.ncol, 1, 80/MAX_IMAGE_NAME);
		number("Entries per column", &mn.maxcol, 1, 30);
		if (mn.ncol > 1) {
		    getXY("Column pitch", &mn.xpitch, 8, 0);
		    number("Spill threshold", &mn.mincol, 1, mn.maxcol);
		}
		break;
	    case 'P':
		getXY("\nTable UL column", &mn.col, 8, 1);
		getXY("Table UL row", &mn.row, 16, 1);
		break;
	    case 'B':
	    	editing = 0;
	    	break;
	    default:
	    	printf("???");
	}
	free(cmd);
	printf("\n");
    } while (editing);
}


static void edit_colors(void)
{
    char *cmd;
    int editing = 1;
    
    do {
	printf("\n");
	show_colors(1);
    	
	printf("\nText color options:  N)ormal, H)ighlight, ");
	if (timer) printf("T)imer, ");
	printf("B)ack:  ");

	cmd = getLine();
	switch(toupper(*cmd)) {
	    case 'N':
		get3colors("Normal text", &mn.fg);
		break;
	    case 'H':
		get3colors("Highlight text", &mn.h_fg);
		break;
	    case 'T':
		if (timer) get3colors("Timer text", &mn.t_fg);
		else goto bad;
		break;
	    case 'B':
	    	editing = 0;
	    	break;
	    default:
	    bad:
	    	printf("???");
	}
	free(cmd);
	printf("\n");
    } while (editing);
}


static void edit_bitmap(char *bitmap_file)
{
    char *cmd;
    int editing = 1;
    
    printf("Editing contents of bitmap file:  %s\n", bitmap_file);
    
    bmp_file_open(bitmap_file);

    do {
	show_layout();
	printf("\nText colors:\n");
	show_colors(0);
	show_timer();
	
	printf("\nCommands are:  L)ayout, C)olors, T)imer, Q)uit, W)rite:  ");
	cmd = getLine();
	switch(toupper(*cmd)) {
	    case 'C':
		edit_colors();
		break;
	    case 'L':
		edit_layout();
		break;
	    case 'T':
		edit_timer();
		break;
	    case 'W':
	        if (yesno("Save companion configuration file?", 0))
						dat_file_creat(bitmap_file);
	    	editing = !yesno("Save changes to bitmap file?", 0);
	    	if (!editing) {
	    	    printf("Writing output file:  %s\n", bitmap_file);
	    	    bmp_file_close(!test);  /* update */
	    	    if (test) printf("***The bitmap file has not been changed***\n");
		}
	    	break;
	    case 'Q':
	    	editing = !yesno("Abandon changes?", 0);
	    	if (!editing) bmp_file_close(0);  /* no update */
	    	break;
	    default:
	    	printf("???");
	}
	free(cmd);
	printf("\n");
    } while (editing);
    exit(0);
}


static void transfer_params(char *config_file)
{
    int n;
    char *bitmap_file, *opt;
    char *cp;
    int cfd;

    cfg_bitmap_only();		/* disable everything but cf_bitmap */
    
    cfd = cfg_open(config_file);
    if (verbose >= 3) printf("cfg_open returns: %d\n", cfd);
    n = cfg_parse(cf_bitmap);
    if (verbose >= 3) printf("cfg_parse returns: %d\n", n);
    if (n != 0) {
	die("Illegal token in '%s'", config_file);
    }
    if ((bitmap_file = cfg_get_strg(cf_bitmap, "bitmap")) != NULL) {
	opt = "Using";
	cp = strrchr(config_file, '/');
	if (cp && bitmap_file[0] != '/') {
	    *++cp = 0;
	    bitmap_file = strcat(strcpy(alloc(strlen(config_file) + strlen(bitmap_file) + 1),
					config_file),
				 bitmap_file);
	    *cp = '/';
	}
    } else {
	opt = "Assuming";
	cp = strrchr(config_file, '.');
	if (cp) *cp = 0;
	bitmap_file = alloc(strlen(config_file) + strlen(BMP_BMP) + 1);
	strcpy(bitmap_file, config_file);
	strcat(bitmap_file, BMP_BMP);
	if (cp) *cp = '.';
    }

    printf("Transfer parameters from '%s' to '%s'", config_file, bitmap_file);
    if (yesno("?", 0)==0) exit(0);

    if (verbose > 0) printf("%s bitmap file:  %s\n", opt, bitmap_file);
    
    bmp_file_open(bitmap_file);
    
    bmp_do_table(cfg_get_strg(cf_bitmap, "bmp-table"), menu);
    bmp_do_colors(cfg_get_strg(cf_bitmap, "bmp-colors"), menu);
    bmp_do_timer(cfg_get_strg(cf_bitmap, "bmp-timer"), menu);
    
    bmp_file_close(1);  /* update */
    
    exit(0);
}


void do_bitmap_edit(char *filename)
{
    char *bmp = BMP_BMP;
    char *fn = strrchr(filename, *bmp);

    if (!fn)
	die ("'%s'/'%s' filename extension required:  %s", BMP_BMP, BMP_CONF, filename);

    if (strcmp(fn, BMP_CONF)==0) transfer_params(filename);
    if (strcmp(fn, BMP_BMP)==0) edit_bitmap(filename);
    
    die("Unknown filename extension:  %s", filename);
}

#undef mn
#else	/* STANDALONE */

static RGB vga_palette[16] = {
/*		 B	 G	 R		*/
	{	000,	000,	000,	0 },	/*  k -- black	*/
	{	170,	000,	000,	0 },	/*  b -- blue	*/
	{	000,	170,	000,	0 },	/*  g -- green	*/
	{	170,	170,	000,	0 },	/*  c -- cyan	*/

/*		 B	 G	 R		*/
	{	000,	000,	170,	0 },	/*  r -- red	*/
	{	170,	000,	170,	0 },	/*  m -- magenta */
	{	000,	 85,	170,	0 },	/*  y -- yellow (amber) */
	{	170,	170,	170,	0 },	/*  w -- white	*/

/*		 B	 G	 R		*/
	{	 85,	 85,	 85,	0 },	/*  K -- BLACK (dark grey) */
	{	255,	000,	000,	0 },	/*  B -- BLUE	*/
	{	000,	255,	000,	0 },	/*  G -- GREEN	*/
	{	255,	255,	000,	0 },	/*  C -- CYAN	*/

/*		 B	 G	 R		*/
	{	000,	000,	255,	0 },	/*  R -- RED	*/
	{	255,	000,	255,	0 },	/*  M -- MAGENTA */
	{	000,	255,	255,	0 },	/*  Y -- YELLOW	*/
	{	255,	255,	255,	0 }	/*  W -- WHITE	*/
			};

FILE* errstd;
static BITMAPLILOHEADER lh;
static int idx[16];

static float hue[NPALETTE], y_yiq[NPALETTE], s_hsv[NPALETTE], 
			s_hls[NPALETTE], v_hsv[NPALETTE], l_hls[NPALETTE];

void gsort(float array[])
{
    int i, j;
    int n=16;
    
    for (j=n-1; j>0; j--) {
	for (i=0; i<j; i++) {
	    if (array[idx[i]] > array[idx[i+1]]) {
		int t = idx[i];
		idx[i] = idx[i+1];
		idx[i+1] = t;
	    }
	}
    }
}

#define MAX(a,b) (a>b?a:b)
#define MIN(a,b) (a<b?a:b)

static void compute_arrays(RGB pal[], int n)
{
    int i;
    float r, g, b, max, min, delta;
    float l, h, mm, hsv, hls;
    
    for (i=0; i<n; i++) {
	idx[i] = i;
	r = NORM(pal[i].red);
	g = NORM(pal[i].green);
	b = NORM(pal[i].blue);
	
	max = MAX(r,g);
	max = MAX(max,b);
	min = MIN(r,g);
	min = MIN(min,b);
	mm = max+min;
	l = mm * 0.5;
	delta = max-min;
	hsv = (max!=0.0 ? delta/max : 0.0);
	if (delta==0.0) {
	    hls = 0.0;
	    h = -1.0;
	} else {
	    hls = delta / ( (mm <= 1.0) ? mm: (2.0 - mm) );
	    h = r==max ? (g - b)/delta :
		g==max ? (b - r)/delta + 2 :
			 (r - g)/delta + 4;
	    h *= 60;
	    if (h < 0) h += 360;
	}
/* compute the YIQ luminance [0..1] */
	y_yiq[i] = r*0.3 + g*0.59 + b*0.11;
	
	l_hls[i] = l;
	s_hls[i] = hls;
	s_hsv[i] = hsv;
	v_hsv[i] = max;
	hue[i] = h;
	
    }  /* for ... */
}


char *Hue(int idx)
{
    static char val[8];
    static const char name[] = "RYGCBM";
    int i;
    float h;
    
    h = hue[idx];
    if (h<0) return "";
    h += 30;
    i = h/60.0;
    h -= i*60.0;
    i %= 6;
    h -= 30;
    if (fabs(h)<0.1) { val[0]=name[i]; val[1]=0; }
    else sprintf(val,"%c%+3.1f", name[i], h);
    
    return val;
}


void printline(RGB pal[], int i)
{
/*	      R   G   B   i     Y      V    S(hsv)   S(hls)   L      H	     */
    printf("(%3d,%3d,%3d)%3d  %6.3f  %6.3f  %6.3f    %6.3f  %6.3f  %+6.1f  %s\n",
    	pal[i].red, pal[i].green, pal[i].blue, i,
    	y_yiq[i], v_hsv[i], s_hsv[i], s_hls[i], l_hls[i], hue[i], Hue(i) );
}


void printpalette(RGB pal[], int n)
{
    int i;
/* 	      R   G   B   i     Y      V    S(hsv)   S(hls)   L      H	     */
printf("   R   G   B   i     Y       V     S-hsv     S-hls     L       H\n");
    for (i=0; i<n; i++)  printline(pal, idx[i]);
    printf("\n");
}


int main(int argc, char *argv[])
{
    int ifd;
    char *outname;
    int i;
/*    char *cc = "kbgcrmywKBGCRMYW";  */
    
    errstd = stderr;
    if (argc < 2) {
        printf("Input file not specified\n");
    	exit(1);
    }
    ifd = open(argv[1], O_RDONLY);
    if (ifd<0) pdie("opening input file");
    if (argc > 2) die("Too many arguments");
    if (argc < 3) outname = "out.bmp";
    else outname = argv[2];

    compute_arrays(vga_palette, 16);
    printf("\nVGA palette:\n\n\n");
    printpalette(vga_palette, 16);
    gsort(y_yiq);
    printf("\n\nVGA pallette by luminance\n\n\n");
    printpalette(vga_palette, 16);
    
    i = get_std_headers(ifd, &fh, &bmh, &lh);
    if (i) {
    	printf("Error exit on GET:  %d\n", i);
    	exit(i);
    }
    printf("\n\n\nContained palette:\n\n");

    compute_arrays(palette, 16);
    
    gsort(y_yiq);
    printpalette(palette, 16);
    
    close(ifd);

    return 0;
}

#endif	/* STANDALONE */
