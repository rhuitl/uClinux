#ident "$Id: pbm2g3.c,v 4.2 1998/05/07 10:37:38 gert Exp $ Copyright (C) 1994 Gert Doering"

/* pbm2g3
 *
 * convert a "portable bitmap" file into CCITT T.4 fax format
 * the output can directly be sent with mgetty+sendfax
 *
 * options: -d     output digifax header
 *          -w xxx use a page width of xxx pels (default 1728)
 *          -h xxx start page with xxx blank lines (default 0)
 *	    -a     byte-align EOLs
 *	    -r     reverse bytes
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "syslibs.h"
#include <ctype.h>

#include "ugly.h"

#include "g3.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

/* g3 stuff */

int byte_align = FALSE;

static unsigned char buf[2048];
static int buflen = 0;
static unsigned int out_data = 0;
static unsigned int out_hibit = 0;

static int out_byte_tab[ 256 ];			/* for g3 byte reversal */

#ifdef __GNUC__
inline
#endif
void putcode _P2( (code, len), int code, int len )
{
    out_data |= ( code << out_hibit );
    out_hibit += len;

    while( out_hibit >= 8 )
    {
	buf[ buflen++ ] = out_byte_tab[( out_data ) & 0xff];
	out_data >>= 8;
	out_hibit -= 8;
	if ( buflen >= sizeof( buf ) )
	{
	    write( 1, buf, buflen ); buflen = 0;
	}
    }
}

#ifdef __GNUC__
inline
#endif
void puteol _P0( void )			/* write byte-aligned EOL */
{
    if ( byte_align ) while( out_hibit != 4 ) putcode( 0, 1 );
    putcode( 0x800, 12 );
}

#ifdef __GNUC__
inline
#endif
void putwhitespan _P1( (l), int l )
{
    if ( l >= 64 )
    {
	int mkup = ( l & ~63 );
	int idx = (mkup / 64) -1;
	
	if ( mkup > 1728 )	/* extended makeup table */
	{
	    fprintf( stderr,
		    "run length too long (%d) - not yet implemented\n",  l );
	    exit(99);
	}
	else
	{
	    if ( m_white[idx].nr_pels != mkup )	/* paranoia alert */
	    {
		fprintf( stderr, "no match: idx=%d, mkup=%d", idx, mkup );
		exit(99);
	    }
	    putcode( m_white[idx].bit_code, m_white[idx].bit_length );
	}
	l -= mkup;
    }

    putcode( t_white[l].bit_code, t_white[l].bit_length );
}

#ifdef __GNUC__
inline
#endif
void putblackspan _P1( (l), int l )
{
    if ( l >= 64 )
    {
	int mkup = ( l & ~63 );
	int idx = (mkup / 64) -1;
	
	if ( mkup > 1728 )	/* extended makeup table */
	{
	    fprintf( stderr,
		    "run length too long (%d) - not yet implemented\n",  l );
	    exit(99);
	}
	else
	{
	    if ( m_black[idx].nr_pels != mkup )	/* paranoia alert */
	    {
		fprintf( stderr, "no match: idx=%d, mkup=%d", idx, mkup );
		exit(99);
	    }
	    putcode( m_black[idx].bit_code, m_black[idx].bit_length );
	}
	l -= mkup;
    }
    
    putcode( t_black[l].bit_code, t_black[l].bit_length );
}

/* pbm file header stuff */

typedef enum { unknown,
	       pbm, pgm, ppm,
	       pbm_raw, pgm_raw, ppm_raw
	   } pbm_file_types;

pbm_file_types	pbm_type;
int		pbm_xsize;
int		pbm_ysize;

int pbm_getint _P1( (fd), int fd )
{
    char buf[50];
    int i;
    
    /* skip leading whitespace */
    do
    {
	if ( read( fd, buf, 1 ) != 1 ) return -1;

	if ( buf[0] == '#' )
	{
	    while( buf[0] != '\n' && read( fd, buf, 1 ) == 1 ) {}
	}
    }
    while ( isspace( buf[0] ) );

    i = 1;
    while ( i < sizeof( buf ) -1 &&
	    read( fd, &buf[i], 1 ) == 1 &&
	    ! isspace( buf[i] ) )
    {
	i++;
    }

    if ( ! isspace( buf[i] ) ) return -1;

    buf[i] = 0;

    return ( atoi( buf ) );
}
 
void pbm_getheader _P1( (fd), int fd )
{
    char buf[10];

    if ( read( fd, buf, 2 ) != 2 || buf[0] != 'P' )
    {
	pbm_type = unknown; return;
    }

    switch( buf[1] )
    {
      case '1': pbm_type = pbm; break;
      case '2': pbm_type = pgm; break;
      case '3': pbm_type = ppm; break;
      case '4': pbm_type = pbm_raw; break;
      case '5': pbm_type = pgm_raw; break;
      case '6': pbm_type = ppm_raw; break;
      default:  pbm_type = unknown; return;
    }

    pbm_xsize = pbm_getint( fd );
    pbm_ysize = pbm_getint( fd );
}



void exit_usage _P1( (name), char * name )
{
    fprintf( stderr,
	     "usage: %s [-w width] [-h blank_lines] [-d] [-a] [-r] [pbm file]\n",
	      name );
    exit(1);
}
     

void convert_pbm_raw _P2( (fd, g3_page_width), int fd, int
			 g3_page_width )
{
    extern void make_run_tables _PROTO((void));
    extern char w_rtab[8][256],
                b_rtab[8][256];

    int x, y, maxx;
    int run, c;
    int bit;

    int ll;
    unsigned char * linebuf, * r;
    
    /* initialize run length tables */
    make_run_tables();

    /* round up page width to byte boundary */
    pbm_xsize = ( pbm_xsize + 7 ) & ~7;

    /* malloc memory for line buffer */
    ll = pbm_xsize / 8;
    linebuf = (unsigned char *) malloc( ll );

    if ( linebuf == NULL )
    {
	fprintf( stderr, "cannot malloc %d bytes: ", ll );
	perror( "" );
	exit(5);
    }

    /* maximum number of PELs to write pbm -> g3 */
    if ( g3_page_width > pbm_xsize ) maxx = pbm_xsize;
                                else maxx = g3_page_width;

    for ( y=0; y<pbm_ysize; y++ )
    {
	int h;
	
	c = 0;					/* start with white */
	run = 0;
	x = 0;
	bit = 7;
	
	/* read line into buffer (pipe -> multiple tries may be necessary!) */
	h = 0;
	while ( h < ll )
	{
	    int h2;
	    
	    h2 = read( fd, linebuf+h, ll-h );
	    if ( h2 == 0 )
	    {
		fprintf( stderr, "line %d: want %d, got %d bytes, EOF", y, ll, h );
		return;		/* the page will be short... */
	    }
	    h += h2;
	}
	
	r = linebuf;
	
	while ( x+run < maxx )
	{
#ifdef NOISY
fprintf( stderr, "c=%d, bit=%d, x=%d, *r(%d)=%03o ", c, bit, x, r-linebuf, *r);
#endif
	    if ( c == 0 )	/* white run */
	    {
		run += w_rtab[ bit ][ *r ];
		bit -= w_rtab[ bit ][ *r ];
	    }
	    else		/* black run */
	    {
		run += b_rtab[ bit ][ *r ];
		bit -= b_rtab[ bit ][ *r ];
	    }
#ifdef NOISY
fprintf( stderr, "-> run=%d, bit=%d\n", run, bit );
#endif
	    if ( bit < 0 )	/* continue in next byte */
	    {
		if ( bit != -1 ) fprintf( stderr, "bit panic: %d\n", bit );
		bit = 7;
		r++;
	    }
	    else		/* write out run, change color */
	    {
		if ( c == 0 )	/* white */
		    putwhitespan( run );
		else		/* black */
		    putblackspan( run );

                x += run;
		run = 0;
		c = !c;
	    }
	}			/* end while ( x+run < maxx ) */
#ifdef NOISY
fprintf( stderr, "end of line, c=%d, run=%d, bit=%d, x=%d\n", c, run, bit, x );
#endif

	/* write rest of line */
	if ( c == 0 ) putwhitespan( run + (g3_page_width - maxx) );
	else
	{
	    putblackspan( run );
	    putwhitespan( g3_page_width - maxx );
	}
        puteol();
    }				/* end for ( all y ) */
}

void convert_pbm _P2( (fd, g3_page_width), int fd, int g3_page_width )
{
    int x, y;
    int c, ch = 0;
    int run;
    FILE * fp;
    int maxx;

    if ( ( fp = fdopen( fd, "r" ) ) == NULL )
    {
	perror( "cannot fdopen: " );
	exit( 5 );
    }

    /* maximum size of PELs to write pbm -> g3 */
    if ( g3_page_width > pbm_xsize ) maxx = pbm_xsize;
                                else maxx = g3_page_width;

    for ( y = 0; y < pbm_ysize; y++ )
    {
	c = '0';	/* start with white run length */
	run = 0;

	x = 0;
	while ( x < maxx && ch != EOF )
	{
	    ch = fgetc( fp );
	    if ( ch == '#' )			/* comment lines */
	    {
		while ( ch != '\n' ) ch = fgetc( fp );
	    }
	    if ( ch == '0' || ch == '1' )	/* bits */
	    {
		x++;
		if ( ch == c ) run++;
		else
		{
		    if ( c == '0' ) putwhitespan( run );
		               else putblackspan( run );
		    c = ch;
		    run = 1;
		}
	    }
	}					/* end while (x<maxx) */

	/* read remainder of line (if pbm was wider than the G3 page) */
	while ( x < pbm_xsize && ch != EOF )
	{
	    ch = fgetc( fp );
	    if ( ch == '#' )			/* comment lines */
	    { while ( ch != '\n' ) ch = fgetc( fp ); }
	    if ( ch == '0' || ch == '1' )	/* bits */
	    { x++; }
	}

	if ( c == '0' ) putwhitespan( run + (g3_page_width - maxx) );
	else
	{
	    putblackspan( run );
	    putwhitespan( g3_page_width - maxx );
	}
	
	puteol();
    }
}


extern int	optind;
extern char *	optarg;

int main _P2( (argc, argv), int argc, char ** argv )
{
    int c, fd, i;
    int empty_lines = 0;
    int g3_page_width = 1728;
    int digifax_header = FALSE;
    
    init_byte_tab( FALSE, out_byte_tab );
    
    while ( (c = getopt(argc, argv, "h:w:dar") ) != EOF)
    {
	switch (c)
	{
	  case 'h': empty_lines = atoi( optarg ); break;
	  case 'w': g3_page_width = atoi( optarg ); break;
	  case 'd': digifax_header = TRUE; break;
	  case 'a': byte_align = TRUE; break;
	  case 'r': init_byte_tab( TRUE, out_byte_tab ); break;
	    
	  default: exit_usage( argv[0] );
	}
    }

    if ( optind == argc	||
	 strcmp( argv[optind], "-" ) == 0 )	/* read from stdin */
    {
	fd = 0;
    }
    else					/* read from file */
    {
	if ( optind != argc -1 ) exit_usage( argv[0] );
	
	fd = open( argv[optind], O_RDONLY );
	if ( fd == -1 )
	{
	    fprintf( stderr, "%s: cannot open %s: ", argv[0], argv[optind] );
	    perror( "" );
	    exit(2);
	}
    }

    /* ok, open succeeded. now get file type */
    pbm_getheader( fd );

    /* reject unknown file types */
    if ( pbm_type == unknown )
    {
	fprintf( stderr, "%s: input file type unknown\n", argv[0] );
	exit(3);
    }

    /* barf if problems reading the header occured */
    if ( pbm_xsize == -1 || pbm_ysize == -1 )
    {
	fprintf( stderr, "%s: error reading PBM header\n", argv[0] );
	exit(4);
    }

    /* unsupported bitmap types */
    
    if ( pbm_type == pgm || pbm_type == pgm_raw )
    {
	fprintf( stderr, "%s: portable greymaps (pgm) not supported, use ``pgmtopbm'' first.\n", argv[0] );
	exit(3);
    }
    if ( pbm_type == ppm || pbm_type == ppm_raw )
    {
	fprintf( stderr, "%s: portable pixmap (ppm) not supported, use ``ppmtopgm | pgmtopbm'' first.\n", argv[0] );
	exit(3);
    }

    /* the only remaing types are PBM and PBM RawBits */


    /* if the g3_page_width is 0, use the width of the pbm file */
    if ( g3_page_width == 0 ) g3_page_width = pbm_xsize;

    /* if it's a RAW pbm file, round up the g3_page_width to
     * multiples of 8 (to avoid byte-boundary problems)
     */
    if ( pbm_type == pbm_raw && g3_page_width < ( ( pbm_xsize+7 ) & ~7) )
    {
	g3_page_width = ( g3_page_width + 7 ) & ~7;
    }
    
    /* output leading EOL and possibly leading blank lines */
    puteol();
    for ( i=0; i<empty_lines; i++ )
    {
	putwhitespan( g3_page_width ); puteol();
    }

    /* convert file */
    if ( pbm_type == pbm )
    {
	convert_pbm( fd, g3_page_width );
    }
    else
    {
	convert_pbm_raw( fd, g3_page_width );
    }
    
    /* over & out */
    close( fd );

    /* output final RTC */
    for ( i=0; i<6; i++ ) puteol();
    
    /* flush buffer */
    if ( out_hibit != 0 )
        buf[buflen++] = out_byte_tab[out_data & 0xff];
    write( 1, buf, buflen );
    
    exit(0);
}
