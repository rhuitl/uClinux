From labinfo.iet.unipi.it!luigi Thu Nov 10 15:19:22 1994
Return-Path: <luigi@labinfo.iet.unipi.it>
Received: by greenie.muc.de (/\==/\ Smail3.1.24.1 #24.2)
	id <m0r5aLL-0002lRC@greenie.muc.de>; Thu, 10 Nov 94 15:19 MET
Received: from labinfo.iet.unipi.it ([131.114.9.5]) by colin.muc.de with SMTP id <25590(1)>; Thu, 10 Nov 1994 15:19:01 +0100
Received: from localhost (luigi@localhost) by labinfo.iet.unipi.it (8.6.5/8.6.5) id PAA01788 for gert@greenie.muc.de; Thu, 10 Nov 1994 15:15:36 +0100
From: Luigi Rizzo <luigi@labinfo.iet.unipi.it>
Message-Id: <199411101415.PAA01788@labinfo.iet.unipi.it>
Subject: Re: mgetty+sendfax
To: gert@greenie.muc.de (Gert Doering)
Date: Thu, 10 Nov 1994 15:15:36 +0100
In-Reply-To: <m0r4ynK-00021XC@greenie.muc.de> from "Gert Doering" at Nov 8, 94 11:13:18 pm
X-Mailer: ELM [version 2.4 PL23]
Content-Type: text
Content-Length: 14459     
Status: RO

Gert,
here is what I have so far.

It is a simple converter based on your g3topbm.c (which resembles very
closely). Just use it as

	g3tops < g3file > /tmp/psfile ; gs /tmp/psfile

I find it faster than converting to pbm and using xv.
Feel free to modify it/incorporate it into the existing g3toxx programs.


	Luigi
--------------------------------------------------------
#define G3PS
#ident "@(#)g3topbm.c	1.18 94/10/31 (c) Gert Doering"

#include <stdio.h>
#include <unistd.h>
#include "syslibs.h"
#include <string.h>
#include <fcntl.h>

#include "ugly.h"

#include "g3.h"

char psheader[]=
    "%!\n0 72 25.4 div 297 mul translate\n"
    "72 204 div 72 98 div scale\n"
    "1 -1 scale\n"
    "/L { 0 rmoveto 0 rlineto} def\n"
    "/P { 1 exch L} def\n"
    "/N { currentpoint stroke 1 add exch pop 0 exch moveto} def\n"
    "/M { currentpoint exch pop add stroke 0 exch moveto} def\n"
    "0 0 moveto\n";
int lastx=0, lastblack= -1;
int whitelines=0;
int  pixblock _PROTO((char *start, char *end));
int  nullscan _PROTO((char *start, char *end));
void emitlj _PROTO((int resolution, int numx, int numy, char *image));

void emitpbm _PROTO((int hcol, int row, char *bitmap, int bperrow ));


#ifdef DEBUG
void putbin _P1( (d), unsigned long d )
{
unsigned long i = 0x80000000;

    while ( i!=0 )
    {
	putc( ( d & i ) ? '1' : '0', stderr );
	i >>= 1;
    }
    putc( '\n', stderr );
}
#endif

static int byte_tab[ 256 ];
static int o_stretch;			/* -stretch: double each line */
static int o_lj;			/* -l: LJ output */
static int o_turn;			/* -t: turn 90 degrees right */

struct g3_tree * black, * white;

#define CHUNK 2048;
static	char rbuf[2048];	/* read buffer */
static	int  rp;		/* read pointer */
static	int  rs;		/* read buffer size */

#define MAX_ROWS 4300
#define MAX_COLS 1728		/* !! FIXME - command line parameter */

#define BASERES 200		/* resolution of G3 */

#define MVTYPE	int

/* scale the bitmap */

char *scalebm _P5( (res, cols, rows, map, bperrow),
		    int res, int *cols, int *rows, char *map, int *bperrow)
{
    int nc, nr, i, newbperrow;
    register char *orp, *nrp;
    char *newmap;
    MVTYPE *mulvec;

    if ( res == BASERES ) 		/* don't do anything of not scaled */
    {
	return map;
    }

    /* do scaling, from "BASERES" to "res" dpi */

    nr = (*rows * res) / BASERES;
    nc = (((*cols * res) / BASERES) + 7) & ~7;
    newbperrow = (nc + 7) >> 3;
    

    newmap = malloc(nr * newbperrow );
    if (!newmap)
    {
	fprintf (stderr, "g3topbm: cannot allocate %d bytes for scale raster\n",
	                 nr * newbperrow );
	exit(1);
    }
    memset( newmap, 0, nr * newbperrow );

    {
	int max = *cols > *rows ? *cols: *rows;
	MVTYPE *mv;

	mulvec = (MVTYPE *) malloc(max * sizeof(MVTYPE));
	if (!mulvec)
	{
	    fprintf (stderr, "g3topbm: cannot allocate multiplier vector\n");
	    exit(1);
	}
	for (mv = mulvec, i = 0; i < max; i++)
	{
	    *mv++ = (i * res) / BASERES;
	}
    }

    orp = map;

    for (i = 0; i < *rows; i++)
    {
	register MVTYPE *mv;
	register int j;
	nrp = newmap + (mulvec[i] * newbperrow);

	for (j = 0, mv = mulvec; j < *cols; j++, mv++)
	{
	    if (!(j & 0x7) && !orp[j >> 3])
	    {
		j += 8;
		mv += 8;
		continue;
	    }

	    if (orp[j >> 3] & (0x80 >> (j & 0x7)))
		    nrp[(*mv) >> 3] |= (0x80 >> ((*mv) & 0x7));
	}
    
	orp += *bperrow;
    }

    free (map);
    *rows = nr;
    *cols = nc;
    *bperrow = newbperrow;
    return (newmap);
}

/* turn the bitmap */

char * turnbm _P4 (( cols, rows, map, bperrow ),
		     int * cols, int * rows, char * map, int * bperrow )
{
char * newmap;
int newbperrow, nr, nc, nx, ny;

register int obit;
register char * newbp, * obyte;

char * oldbp;
int byte, bit;

    o_turn &= 3;
    if ( o_turn == 0 ) return map;

    /* turn right */
    nc = *rows;		/* new columns */
    nr = *cols;		/* new rows */
    newbperrow = ( nc+7 ) / 8;

    newmap = malloc( nr * newbperrow );

    if ( newmap == NULL )
    {
	fprintf( stderr, "g3topbm: cannot allocate %d bytes for turn bitmap",
			 nr * newbperrow );
	exit(1);
    }

    memset( newmap, 0, nr * newbperrow );

    for( nx = 0; nx<nc; nx++ )			/* new X coordinate */
    {
	bit  = 0x80 >> (nx&7);
	byte = nx >> 3;

	oldbp = &map[ (*rows - nx - 1) * *bperrow ];

	for ( ny = nr, newbp= &newmap[byte],	/* new y */
	      obyte = oldbp, obit=0x80;
	      ny>0; ny--, newbp += newbperrow )
	{
	    if ( (*obyte) & obit ) 
	    {
		*newbp |= bit;
	    }
	    obit >>= 1; if ( obit == 0 ) { obit=0x80; obyte++; }
	}
    }

    free( map );
    *rows = nr;
    *cols = nc;
    *bperrow = newbperrow;
    return newmap;
}

int main _P2( (argc, argv), int argc, char ** argv )
{
int data;
int hibit;
struct	g3_tree * p;
int	nr_pels;
int fd;
int color;
int i;
int cons_eol;

int	bperrow = MAX_COLS/8;	/* bytes per bit row */
char *	bitmap;			/* MAX_ROWS by (bperrow) bytes */
char *	bp;			/* bitmap pointer */
int	row;
int	max_rows;		/* max. rows allocated */
int	col, hcol;		/* column, highest column ever used */
extern  int optind;
extern  char *optarg;
int	resolution = BASERES;

    /* initialize lookup trees */
    build_tree( &white, t_white );
    build_tree( &white, m_white );
    build_tree( &black, t_black );
    build_tree( &black, m_black );

    init_byte_tab( 0, byte_tab );

    while((i = getopt(argc, argv, "rsld:t")) != EOF)
    {
	switch (i)
	{
	    case 'r':
		init_byte_tab( 1, byte_tab );
		break;
	    case 's':
		o_stretch=1;
		break;
	    case 'l':
		o_lj=1;
		break;
	    case 'd':
		resolution = atoi(optarg);
		if ( resolution != 75 && resolution != 150 &&
		     resolution != 300 )
		{
		    fprintf( stderr, "g3topbm: only supports 75, 150, or 300 dpi\n");
		    exit(1);
		}
		break;
	    case 't':
		o_turn++;
		break;
	    case '?':
		fprintf( stderr, "usage: g3topbm [-l|-r|-s|-d <dpi>|-t] [g3 file]\n");
		exit(1);
	}
    }

    if (o_lj && resolution == BASERES)
	resolution = 150;

    if ( optind < argc ) 			/* read from file */
    {
	fd = open( argv[optind], O_RDONLY );
	if ( fd == -1 )
	{    perror( argv[optind] ); exit( 1 ); }
    }
    else
	fd = 0;

    hibit = 0;
    data = 0;

    cons_eol = 0;	/* consecutive EOLs read - zero yet */

    color = 0;		/* start with white */

    rs = read( fd, rbuf, sizeof(rbuf) );
    if ( rs < 0 ) { perror( "read" ); close( rs ); exit(8); }

			/* skip GhostScript header */
    rp = ( rs >= 64 && strcmp( rbuf+1, "PC Research, Inc" ) == 0 ) ? 64 : 0;

    /* initialize bitmap */

    row = col = hcol = 0;
    bitmap = (char *) malloc( ( max_rows = MAX_ROWS ) * MAX_COLS / 8 );
    if ( bitmap == NULL )
    {
	fprintf( stderr, "cannot allocate %d bytes for bitmap",
		 max_rows * MAX_COLS/8 );
	close( fd );
	exit(9);
    }
    memset( bitmap, 0, max_rows * MAX_COLS/8 );
    bp = &bitmap[ row * MAX_COLS/8 ]; 

#ifdef G3PS
    fprintf(stdout,"%s",psheader);
#endif /* G3PS */
    while ( rs > 0 && cons_eol < 4 )	/* i.e., while (!EOF) */
    {
#ifdef DEBUG
	fprintf( stderr, "hibit=%2d, data=", hibit );
	putbin( data );
#endif
	while ( hibit < 20 )
	{
	    data |= ( byte_tab[ (int) (unsigned char) rbuf[ rp++] ] << hibit );
	    hibit += 8;

	    if ( rp >= rs )
	    {
		rs = read( fd, rbuf, sizeof( rbuf ) );
		if ( rs < 0 ) { perror( "read2"); break; }
		rp = 0;
		if ( rs == 0 ) { goto do_write; }
	    }
#ifdef DEBUG
	    fprintf( stderr, "hibit=%2d, data=", hibit );
	    putbin( data );
#endif
	}

	if ( color == 0 )		/* white */
	    p = white->nextb[ data & BITM ];
	else				/* black */
	    p = black->nextb[ data & BITM ];

	while ( p != NULL && ! ( p->nr_bits ) )
	{
	    data >>= BITS;
	    hibit -= BITS;
	    p = p->nextb[ data & BITM ];
	}

	if ( p == NULL )	/* invalid code */
	{ 
	    fprintf( stderr, "invalid code, row=%d, col=%d, file offset=%lx, skip to eol\n",
		     row, col, (unsigned long) lseek( fd, 0, 1 ) - rs + rp );
	    while ( ( data & 0x03f ) != 0 )
	    {
		data >>= 1; hibit--;
		if ( hibit < 20 )
		{
		    data |= ( byte_tab[ (int) (unsigned char) rbuf[ rp++] ] << hibit );
		    hibit += 8;

		    if ( rp >= rs )	/* buffer underrun */
		    {   rs = read( fd, rbuf, sizeof( rbuf ) );
			if ( rs < 0 ) { perror( "read4"); break; }
			rp = 0;
			if ( rs == 0 ) goto do_write;
		    }
		}
	    }
	    nr_pels = -1;		/* handle as if eol */
	}
	else				/* p != NULL <-> valid code */
	{
	    data >>= p->nr_bits;
	    hibit -= p->nr_bits;

	    nr_pels = ( (struct g3_leaf *) p ) ->nr_pels;
#ifdef DEBUG
	    fprintf( stderr, "PELs: %d (%c)\n", nr_pels, '0'+color );
#endif
	}

	/* handle EOL (including fill bits) */
	if ( nr_pels == -1 )
	{
#ifdef G3PS
	whitelines++; /*fprintf(stdout,"N\n"); */
	lastx=0; lastblack= -1;
#endif
#ifdef DEBUG
	    fprintf( stderr, "hibit=%2d, data=", hibit );
	    putbin( data );
#endif
	    /* skip filler 0bits -> seek for "1"-bit */
	    while ( ( data & 0x01 ) != 1 )
	    {
		if ( ( data & 0xf ) == 0 )	/* nibble optimization */
		{
		    hibit-= 4; data >>= 4;
		}
		else
		{
		    hibit--; data >>= 1;
		}
		/* fill higher bits */
		if ( hibit < 20 )
		{
		    data |= ( byte_tab[ (int) (unsigned char) rbuf[ rp++] ] << hibit );
		    hibit += 8;

		    if ( rp >= rs )	/* buffer underrun */
		    {   rs = read( fd, rbuf, sizeof( rbuf ) );
			if ( rs < 0 ) { perror( "read3"); break; }
			rp = 0;
			if ( rs == 0 ) goto do_write;
		    }
		}
#ifdef DEBUG
	    fprintf( stderr, "hibit=%2d, data=", hibit );
	    putbin( data );
#endif
	    }				/* end skip 0bits */
	    hibit--; data >>=1;
	    
	    color=0; 

	    if ( col == 0 )
		cons_eol++;		/* consecutive EOLs */
	    else
	    {
	        if ( col > hcol && col <= MAX_COLS ) hcol = col;
		row++;

		/* bitmap memory full? make it larger! */
		if ( row >= max_rows )
		{
		    char * p = realloc( bitmap,
				       ( max_rows += 500 ) * MAX_COLS/8 );
		    if ( p == NULL )
		    {
			perror( "realloc() failed, page truncated" );
			rs = 0;
		    }
		    else
		    {
			bitmap = p;
			memset( &bitmap[ row * MAX_COLS/8 ], 0,
			       ( max_rows - row ) * MAX_COLS/8 );
		    }
		}
			
		col=0; bp = &bitmap[ row * MAX_COLS/8 ]; 
		cons_eol = 0;
	    }
	}
	else		/* not eol */
	{
	    if ( col+nr_pels > MAX_COLS ) nr_pels = MAX_COLS - col;

	    if ( color == 0 )                  /* white */
		col += nr_pels;
	    else                               /* black */
	    {
            register int bit = ( 0x80 >> ( col & 07 ) );
	    register char *w = & bp[ col>>3 ];

		for ( i=nr_pels; i > 0; i-- )
		{
		    *w |= bit;
		    bit >>=1; if ( bit == 0 ) { bit = 0x80; w++; }
		    col++;
		}
	    }
	    if ( nr_pels < 64 ) {
		color = !color;		/* terminating code */
#ifdef G3PS
		if (color) { /* black begins */
		    lastblack= col;
		} else { /* black ends */
		    int black=col- lastblack;
		    int move=lastblack - lastx;
		    if (lastblack > -1) {
			if (whitelines>1) fprintf(stdout,"%d M\n",whitelines);
			else if (whitelines==1) fprintf(stdout,"N\n");
			whitelines=0;
			fprintf(stdout,"%d %d L\n",black, move);
		    }
		    lastx=col; lastblack= -1;
		}
#endif
	    }
	}
    }		/* end main loop */

do_write:      	/* write pbm (or whatever) file */
#ifdef G3PS
fprintf(stdout,"showpage\n");
exit(0);
#endif

    if( fd != 0 ) close(fd);	/* close input file */

#ifdef DEBUG
    fprintf( stderr, "consecutive EOLs: %d, max columns: %d\n", cons_eol, hcol );
#endif

    bitmap = scalebm(resolution, &hcol, &row, bitmap, &bperrow );

    bitmap = turnbm( &hcol, &row, bitmap, &bperrow );

    if (o_lj)
	emitlj(resolution, hcol, row, bitmap);
    else
	emitpbm(hcol, row, bitmap, bperrow );


    return 0;
}

/* hcol is the number of columns, row the number of rows
 * bperrow is the number of bytes actually used by hcol, which may
 * be greater than (hcol+7)/8 [in case of an unscaled g3 image less
 * than 1728 pixels wide]
 */

void emitpbm _P4(( hcol, row, bitmap, bperrow),
		   int hcol, int row, char *bitmap, int bperrow )
{
    register int i;

    sprintf( rbuf, "P4\n%d %d\n", hcol, ( o_stretch? row*2 : row ) );
    write( 1, rbuf, strlen( rbuf ));

    if ( hcol == (bperrow*8) && !o_stretch )
        write( 1, bitmap, row * bperrow );
    else
    {
	if ( !o_stretch )
	  for ( i=0; i<row; i++ )
	{
	    write( 1, &bitmap[ i*bperrow ], (hcol+7)/8 );
	}
	else				/* Double each row */
	  for ( i=0; i<row; i++ )
        {
	    write( 1, &bitmap[ i*bperrow ], (hcol+7)/8 );
	    write( 1, &bitmap[ i*bperrow ], (hcol+7)/8 );
	}
    }
}

/* The following code is copyright 1994, Chris Lewis.  Permission is hereby
   permanently granted to Gert Doering to include this software in his
   g3topbm program, whether distributed as freeware or commercially.
 */

#define ESCLEN	25	/* avg # bytes in raster escape prolog/epilog */

int nullscan _P2((start, end), char *start, char *end)
{
    register char *cur;
    for (cur = start; cur < end && !*cur; cur++);
    return(cur - start);
}

int pixblock _P2((start, end), char *start, char *end)
{
    register char *cur;
    register int numnulls;
    if (end - start <= ESCLEN * 2)	/* no point optimizing */
	return(end - start);
    cur = start;

    while(cur < end) {

	for(; *cur && cur < end; cur++);

	numnulls = nullscan(cur, end);

	if (numnulls > ESCLEN)
	    return(cur - start);
	else
	    cur += numnulls;
    }
    return(end - start);
}

void emitlj _P4((resolution, numx, numy, image),
		int resolution, int numx, int numy, char *image)
{
    int bperline;
    int resmult = 300/resolution;
    register char *ip, *lineanch, *nip;
    register currow, bcount;
    bperline = ((numx + 7) / 8);

    /* some spoolers use a "cut" to do printer-type selection
       (eg: "%!" processing).  The newline is to prevent cut
       (or other line-length-limited UNIX utilities) dying. */
    printf("\033*t%dR\n", resolution);

    for(currow = 0; currow < numy; currow++)
    {
	lineanch = ip = &image[bperline * currow];
	nip = ip + bperline;
	while (ip < nip && !*ip) ip++;
	if (ip >= nip)
	    continue;	/* line has no pixels */
	while (!*(nip - 1)) nip--;	/* truncate trailing nulls */
	while (ip < nip) {	/* inv: !*ip && !*nip */
	    bcount = pixblock(ip, nip);
	    printf("\033*p%dx%dY\033*r1A\033*b%dW",
		(ip - lineanch) * 8 * resmult, (currow * resmult) << o_stretch, bcount);
	    fwrite(ip, 1, bcount, stdout);
	    if (o_stretch) {
		printf("\033*b%dW", bcount);
		fwrite(ip, 1, bcount, stdout);
	    }
	    fputs("\033*rB", stdout);
	    for(ip += bcount; ip < nip && !*ip; ip++);
	}
    }
    putchar('\f');
}
/****** end of file **********/

