#ident "$Id: g3cat.c,v 4.5 2005/02/27 19:03:37 gert Exp $ (c) Gert Doering"

/* g3cat.c - concatenate multiple G3-Documents
 *
 * (Second try. Different algorithm.)
 *
 * Syntax: g3cat [options] [file(s) (or "-" for stdin)]
 *
 * Valid options: -l (separate g3 files with a black line)
 *                -d (output digifax header)
 *                -a (byte-align EOLs)
 *		  -h <lines> put <lines> empty lines on top of page
 *		  -p <pad>   zero-fill all lines up to <pad> bytes
 */

/* #define DEBUG 1 */

#include <stdio.h>
#ifndef _NOSTDLIB_H
#include <stdlib.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

extern int	optind;
extern char *	optarg;

#include "ugly.h"
#include "g3.h"

int byte_align = 0;

static unsigned char buf[8192];
static int buflen = 0;
static unsigned int out_data = 0;
static unsigned int out_hibit = 0;

static int out_byte_tab[ 256 ];
static int byte_tab[ 256 ];

static int padding = 0;			/* default: no padding done */
static int b_written = 0;		/* bytes of a line already */
					/* written */

#ifdef __GNUC__
inline
#endif
void putcode _P2( (code, len), int code, int len )
{
#ifdef DEBUG
    fprintf( stderr, "putcode: %03x (%d)\n", code, len );
#endif
    out_data |= ( code << out_hibit );
    out_hibit += len;

    while( out_hibit >= 8 )
    {
	buf[ buflen++ ] = out_byte_tab[( out_data ) & 0xff];
	out_data >>= 8;
	out_hibit -= 8;
	if ( buflen >= sizeof( buf ) )
	{
	    write( 1, buf, buflen ); b_written += buflen; buflen = 0;
	}
    }
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

#ifdef __GNUC__
inline
#endif
void puteol _P0( void )			/* write byte-aligned EOL */
{
    static int last_buflen = 0;
    
    if ( padding > 0 )			/* padding? */
    {
	while( out_hibit != 4 ) putcode( 0, 1 );	/* implies */
							/* aligning */
	while( ( buflen + b_written ) - last_buflen < padding )
	{
	    putcode( 0, 8 );
	}
	last_buflen = buflen;
	b_written = 0;
    }
	
    if ( byte_align ) while( out_hibit != 4 ) putcode( 0, 1 );
    putcode( 0x800, 12 );
}

static	int putblackline = 0;	/* do not output black line */	

static	char rbuf[8192];	/* read buffer */
static	int  rp;		/* read pointer */
static	int  rs;		/* read buffer size */

struct g3_tree *white, *black;

void exit_usage _P1( (program), char * program )
{
    fprintf( stderr, "usage: %s [-h <lines>] [-a] [-l] [-p <n>] [-w <n>] g3-file ...\n",
	    program );
    exit(1);
}

static int have_warned = 0;		/* warn only once per file */
void warn_g3 _P1( (file), char * file )
{
    if ( have_warned ) return;
    fprintf( stderr, "WARNING: G3 file \"%s\" has incorrect line width, fixed\n",
             file );
    have_warned++;
}
    

int main _P2( (argc, argv),
	      int argc, char ** argv )
{
    int i;				/* argument count */
    int fd;				/* file descriptor */
    unsigned int data;		/* read word */
    int hibit;			/* highest valid bit in "data" */

    int cons_eol;
    int color;
    int row, col;
    struct g3_tree * p;
    int nr_pels;
    int first_file = 1;		/* "-a" flag has to appear before */
				/* starting the first g3 file */
    int empty_lines = 0;	/* blank lines at top of page */
    int line_width = 1728;	/* "force perfect" G3 file */
    int opt_R = 0;		/* suppress generation of RTC */
    int max_length = 0;		/* limit max. G3 file length */

    int lines_out = 0;		/* total lines in output file */

    /* initialize lookup trees */
    build_tree( &white, t_white );
    build_tree( &white, m_white );
    build_tree( &black, t_black );
    build_tree( &black, m_black );

    init_byte_tab( 0, byte_tab );
    init_byte_tab( 0, out_byte_tab );

    /* process the command line
     */

    while ( (i = getopt(argc, argv, "lah:p:w:RL:")) != EOF )
    {
	switch (i)
	{
	  case 'l': putblackline = 1; break;
	  case 'a': byte_align = 1; break;
	  case 'h': empty_lines = atoi( optarg ); break;
	  case 'p': padding = atoi( optarg ); break;
	  case 'w': line_width = atoi( optarg ); break;
	  case 'R': opt_R = 1; break;
	  case 'L': max_length = atoi( optarg ); break;
	  case '?': exit_usage(argv[0]); break;
	}
    }

    if ( line_width < 100 )
    {
        fprintf( stderr, "%s: line width must be >= 100 PELs\n", argv[0] );
        exit(1);
    }
	    
    for ( i=optind; i<argc; i++ )
    {
	/* '-l' option may be embedded */
        if ( strcmp( argv[i], "-l" ) == 0)
        {
	    putblackline = 1; continue;
        }
		
	/* process file(s), one by one */
	if ( strcmp( argv[i], "-" ) == 0 )
		fd = 0;
	else
		fd = open( argv[i], O_RDONLY );

	if ( fd == -1 ) { perror( argv[i] ); continue; }

	if ( first_file )
	{
	    if ( byte_align || padding > 0 ) putcode( 0, 4 );
	    putcode( 0x800, 12 );			/* EOL (w/o */
							/* padding) */
	    first_file = 0;
	    while ( empty_lines-- > 0 )			/* leave space at */
							/* top of page */
	    {
		putwhitespan( line_width );
		puteol();
		lines_out++;
	    }
	}
	
	hibit = 0;
	data = 0;

	cons_eol = 0;		/* consecutive EOLs read - zero yet */

	color = 0;		/* start with white */

	have_warned = 0;
	rs = read( fd, rbuf, sizeof(rbuf) );
	if ( rs < 0 ) { perror( "read" ); close( rs ); exit(8); }

			    /* skip GhostScript header */
	rp = ( rs >= 64 && strcmp( rbuf+1, "PC Research, Inc" ) == 0 ) ? 64 : 0;

	row = col = 0;

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
		    if ( rs == 0 ) {
#ifdef DEBUG
			fprintf( stderr, "EOF!" );
#endif
			goto do_write;}
		}
#ifdef DEBUG
		fprintf( stderr, "hibit=%2d, data=", hibit );
		putbin( data );
#endif
	    }

#if DEBUG > 1
	    if ( color == 0 )
		print_g3_tree( "white=", white );
	    else
		print_g3_tree( "black=", black );
#endif

	    if ( color == 0 )		/* white */
		p = white->nextb[ data & BITM ];
	    else				/* black */
		p = black->nextb[ data & BITM ];

	    while ( p != NULL && ! ( p->nr_bits ) )
	    {
#if DEBUG > 1
		print_g3_tree( "p=", p );
#endif
		data >>= BITS;
		hibit -= BITS;
		p = p->nextb[ data & BITM ];
	    }

	    if ( p == NULL )	/* invalid code */
	    { 
		fprintf( stderr, "invalid code, row=%d, col=%d, file offset=%lx, skip to eol\n",
			 row, col, (unsigned long)lseek( 0, 0, 1 ) - rs + rp );
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
#if DEBUG > 1
		print_g3_tree( "p=", p );
#endif
		data >>= p->nr_bits;
		hibit -= p->nr_bits;

		nr_pels = ( (struct g3_leaf *) p ) ->nr_pels;
	    }

	    /* handle EOL (including fill bits) */
	    if ( nr_pels == -1 )
	    {
#ifdef DEBUG
		fprintf( stderr, "hibit=%2d, data=", hibit );
		putbin( data );
#endif
		/* fill up line width, if necessary */
		if ( col>0 && col < line_width )
		{
		    warn_g3( argv[i] );
#ifdef WDEBUG
		    fprintf( stderr, "row: %d, col: %d, line_width: %d\n",
		    		row, col, line_width );
#endif
		    if ( color != 0 )			/* black? */
			{ putblackspan(0); }		/* 0 pix black */
		    putwhitespan( line_width - col );	/* fill w/ white */
		}

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
#ifdef DEBUG
		fprintf( stderr, "EOL!\n" );
#endif
		if ( col == 0 )
		    cons_eol++;
		else
		{
		    row++; col=0;
		    cons_eol = 0;
		    puteol();
		    lines_out++;
		    if ( max_length > 0 && 
			 lines_out >= max_length ) { goto do_write; }
		}
	    }
	    else		/* not eol, write out code */
	    {
	    	if ( col + nr_pels <= line_width )	/* line width in limit */
	    	{
		    /* output same code to g3 file on stdout */
		    putcode( ( (struct g3_leaf *) p ) ->bit_code,
			     ( (struct g3_leaf *) p ) ->bit_length );

		    col += nr_pels;
		}
		else					/* line too long */
		{					/* ->truncate */
		    int put_pels = (line_width - col);
		    warn_g3( argv[i] );
#ifdef WDEBUG
		    fprintf( stderr, "truncate %d to %d (row %d, col %d)\n", nr_pels, put_pels, row, col );
#endif
		    if ( put_pels > 0 )			/* anything left? */
		    {
		        if ( color == 0 )	/* white */
		            putwhitespan( put_pels );
			else
			    putblackspan( put_pels );
		    }
		    col = line_width+1;			/* do not write more to file */
		}

		if ( nr_pels < 64 ) color = !color;	/* terminal code */
	    }
	}		/* end processing one file */
do_write:      		/* write eol, separating lines, next file */

	if( fd != 0 ) close(fd);	/* close input file */

	/* if maximum lines has been reached, leave outer loop */
	if ( max_length > 0 && 
	     lines_out >= max_length ) { break; }

#ifdef DEBUG
	fprintf( stderr, "%s: number of EOLs: %d (%d)\n", argv[i], eols,cons_eols );
#endif
	/* separate multiple files with a line */
	if ( i != argc -1 )
	{
	    putwhitespan( line_width );			/* white line */
	    puteol();
            if ( putblackline )                         /* black line */
		{ putwhitespan( 0 );
		  putblackspan( line_width );
		  puteol(); }
	    putwhitespan( line_width );			/* white line */
	    puteol();
	}

    }	/* end for (all arguments) */

    if ( ! opt_R )
    {
	/* output final RTC */
	for ( i=0; i<6; i++ ) puteol();
    }

    /* flush buffer */
    if ( out_hibit != 0 )
        buf[buflen++] = out_byte_tab[out_data & 0xff];
    write( 1, buf, buflen );

    if ( first_file )
    {
	fprintf( stderr, "%s: warning: no input file specified, empty g3 file created\n", argv[0] );
    }

    return 0;
}
